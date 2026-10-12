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
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use wyrd_format::envelope::VERSION as ENVELOPE_VERSION;
use wyrd_sync::control::{ControlError, CONTROL_VERSION};
use wyrd_sync::durable::{probe_lock, DurableError, LockProbe};
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

/// The archive's platform against this host. Release archives are
/// per-platform; swapping in a foreign binary fails late at
/// `run_preflight` ("failed to execute"), so the mismatch is
/// refused here with the platforms named. Unknown hosts (neither
/// macOS nor Linux) cannot judge and proceed — the preflight stays
/// the backstop.
fn host_platform() -> (Option<&'static str>, Option<&'static str>) {
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

/// Transaction phases (`docs/update.md` §4). `Committed` needs no
/// variant: commit removes the state file, so a present record is
/// always an interrupted transaction converging back or forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    /// New binary staged at `<exe>.next`, old binary untouched.
    Staged,
    /// Renames done, verification not yet passed.
    Swapped,
    /// Verification passed, prev-removal and state-removal pending.
    Verified,
}

/// The transaction record beside the target executable: which drive
/// the swap serves, which archive it came from, and how far it got.
/// Presence alone means "interrupted" — every `wyrd update`
/// invocation converges it before starting anything new.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateState {
    version: u8,
    drive: PathBuf,
    archive_name: String,
    archive_version: String,
    archive_blake3: String,
    phase: Phase,
}

/// What converging a leftover record did. All three leave the
/// installation runnable: the only unwinding is deletion and the
/// one atomic restore rename.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Converged {
    /// No record: nothing to converge.
    Clean,
    /// Rolled back to the pre-swap binary, with the reason.
    RolledBack(String),
    /// Completed a verified commit's cleanup, with the version kept.
    Committed(String),
}

/// Sibling paths of the target executable. Same directory means
/// same filesystem, so every swap step is one atomic rename.
/// `OsString` push keeps the full file name (`wyrd.next`, never
/// `wyrd.next` vs `wyrd` extension surgery across toolchains).
fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(suffix);
    exe.with_file_name(name)
}

fn next_path(exe: &Path) -> PathBuf {
    sibling(exe, ".next")
}

fn prev_path(exe: &Path) -> PathBuf {
    sibling(exe, ".prev")
}

fn state_path(exe: &Path) -> PathBuf {
    sibling(exe, ".update-state")
}

fn stage_dir(exe: &Path) -> PathBuf {
    sibling(exe, ".stage")
}

fn read_state(exe: &Path) -> Result<Option<UpdateState>, CliError> {
    let path = state_path(exe);
    match fs::read(&path) {
        Ok(bytes) => {
            let state: UpdateState = serde_json::from_slice(&bytes).map_err(|_| {
                CliError::Usage(format!(
                    "{}: unreadable update state; remove it only when no update is running",
                    path.display()
                ))
            })?;
            if state.version != 1 {
                return Err(CliError::Usage(format!(
                    "{}: unknown update state version {}",
                    path.display(),
                    state.version
                )));
            }
            Ok(Some(state))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CliError::Io { path, source }),
    }
}

fn write_state(exe: &Path, state: &UpdateState) -> Result<(), CliError> {
    let path = state_path(exe);
    let bytes = serde_json::to_vec_pretty(state).expect("state serializes");
    let tmp = sibling(exe, ".update-state.tmp");
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

/// Remove-if-present plus directory sync, for symmetry with
/// `rename_durable`: a power race over an unsynced removal can
/// only resurrect residue (never the wrong binary — every
/// placement is a synced rename, and the next update converges
/// residue), but uniformity beats a comment explaining why this
/// one site is exempt. The sync targets the removed path's own
/// parent: every call site passes an `exe` sibling, so no
/// second parameter can disagree.
fn remove_if_present(path: &Path) -> Result<(), CliError> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CliError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fsync_dir(&parent_dir(path)?)
}

fn remove_dir_if_present(path: &Path) -> Result<(), CliError> {
    match fs::remove_dir_all(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CliError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fsync_dir(&parent_dir(path)?)
}

/// Sync a directory's entries to durability: after a rename lands
/// a name, only the directory fsync makes it crash-durable. The
/// store this command verifies uses temp + fsync + rename +
/// fsync-dir for exactly this reason; the transaction record and
/// the executable swaps get the same treatment. Unix-only in
/// effect (every rename it follows is a Unix-tested path);
/// elsewhere a no-op keeps non-Unix builds compiling.
fn fsync_dir(dir: &Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let file = fs::File::open(dir).map_err(|source| CliError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        file.sync_all().map_err(|source| CliError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

fn parent_dir(exe: &Path) -> Result<PathBuf, CliError> {
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| CliError::Usage(format!("{}: no parent directory", exe.display())))
}

/// Rename plus directory sync: the rename lands the name, the
/// fsync makes it crash-durable. Every executable move in the
/// transaction goes through here — an unsynced rename that loses
/// a power race leaves the wrong binary (or none) in place with
/// a record describing the other outcome.
fn rename_durable(from: &Path, to: &Path, exe: &Path) -> Result<(), CliError> {
    fs::rename(from, to).map_err(|source| CliError::Io {
        path: to.to_path_buf(),
        source,
    })?;
    fsync_dir(&parent_dir(exe)?)
}

/// Converge a leftover transaction record before starting anything
/// new (`docs/update.md` §4 recovery rule). The rule is one line:
/// only a passed verification commits — everything else rolls
/// back to the pre-swap binary.
///
/// Crash-window ordering bounds the states. The live transaction
/// writes `Swapped` between the two renames, so a record always
/// matches reality except in one window — crash after the first
/// rename, before the record — where the executable is missing
/// with prev present. The unwind prefix below converges exactly
/// that window for every phase; rename atomicity covers the rest.
pub(crate) fn converge(exe: &Path) -> Result<Converged, CliError> {
    let Some(state) = read_state(exe)? else {
        // No record — but an executable missing beside a
        // rollback copy is still an unwinding: the live
        // transaction crashes between its first rename and its
        // record write with exactly this shape, and leaving it
        // means the next update swaps onto nothing.
        if !exe.is_file() && prev_path(exe).is_file() {
            rename_durable(&prev_path(exe), exe, exe)?;
            return Ok(Converged::RolledBack(
                "restored pre-update binary with no record".into(),
            ));
        }
        return Ok(Converged::Clean);
    };
    let next = next_path(exe);
    let prev = prev_path(exe);
    // Unwind prefix: an interrupted swap may have removed the
    // executable before recording it. Restoring prev first
    // converges that window whatever the recorded phase; the
    // flag tells the Swapped arm the restore already happened.
    let prefix_restored = if !exe.is_file() {
        if !prev.is_file() {
            return Err(CliError::Usage(format!(
                "interrupted update of {} left no binary and no {} to restore; \
                 reinstall {} and remove {}",
                state.archive_name,
                prev.display(),
                state.archive_name,
                state_path(exe).display(),
            )));
        }
        rename_durable(&prev, exe, exe)?;
        true
    } else {
        false
    };
    match state.phase {
        // Never swapped: the old binary is in place by
        // construction. Drop the staging and the record.
        Phase::Staged => {
            remove_if_present(&next)?;
            remove_dir_if_present(&stage_dir(exe))?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::RolledBack(format!(
                "removed unstaged {}",
                state.archive_name
            )))
        }
        // Swapped but never verified: restore the old binary. The
        // unwind prefix above already repaired the between-renames
        // window (flagged: prev is spent, the executable is the
        // restored old binary, nothing more to move). Prev present
        // means the new binary is in place and gets replaced. Prev
        // missing with no prefix restore means an operator removed
        // the rollback copy — the one catastrophic case, named as
        // manual recovery instead of implied rollback.
        Phase::Swapped => {
            if prev.is_file() {
                rename_durable(&prev, exe, exe)?;
            } else if !prefix_restored {
                return Err(CliError::Usage(format!(
                    "interrupted update of {} has no {} to restore; \
                     the binary in place is unverified — reinstall {} and remove {}",
                    state.archive_name,
                    prev.display(),
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            remove_if_present(&next)?;
            remove_dir_if_present(&stage_dir(exe))?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::RolledBack(format!(
                "restored pre-update binary after interrupted {}",
                state.archive_name
            )))
        }
        // Verified but cleanup pending: the binary in place passed.
        // Complete the commit — remove the rollback copy and the
        // record — rather than downgrading a verified binary. If
        // the prefix restored, the verified binary itself is gone
        // (only the old rollback copy survived): committing that
        // as verified would be a lie, so this refuses with the
        // reinstall path instead.
        Phase::Verified => {
            if prefix_restored {
                return Err(CliError::Usage(format!(
                    "verified update of {} lost its binary; only the pre-update copy survived — \
                     reinstall {} and remove {}",
                    state.archive_version,
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            if !exe.is_file() {
                return Err(CliError::Usage(format!(
                    "verified update of {} left no binary in place; \
                     reinstall {} and remove {}",
                    state.archive_name,
                    state.archive_name,
                    state_path(exe).display(),
                )));
            }
            remove_if_present(&prev)?;
            remove_if_present(&state_path(exe))?;
            Ok(Converged::Committed(state.archive_version))
        }
    }
}

/// Extract the new binary from the archive into `<exe>.next` and
/// record the staged phase. The archive holds `*/bin/wyrd` (the
/// shape `build.sh --verify` checks); extraction runs the system
/// `tar`, the same prerequisite the release script assumes. A
/// broken archive fails here — pure, before anything is staged —
/// so the state file is written only on success.
pub(crate) fn stage_archive(
    exe: &Path,
    drive: &Path,
    archive: &Path,
    identity: &ArchiveIdentity,
) -> Result<(), CliError> {
    let stage = stage_dir(exe);
    remove_dir_if_present(&stage)?;
    fs::create_dir_all(&stage).map_err(|source| CliError::Io {
        path: stage.clone(),
        source,
    })?;
    let tar = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&stage)
        .output()
        .map_err(|source| {
            CliError::Usage(format!(
                "tar extraction failed ({source}); tar is required to unpack release archives"
            ))
        })?;
    if !tar.status.success() {
        remove_dir_if_present(&stage)?;
        return Err(CliError::Usage(format!(
            "{}: not an unpackable release archive (tar: {})",
            archive.display(),
            String::from_utf8_lossy(&tar.stderr).trim(),
        )));
    }
    let binary = find_staged_binary(&stage).ok_or_else(|| {
        CliError::Usage(format!(
            "{}: no */bin/wyrd inside; release archives carry the binary at <top>/bin/wyrd",
            archive.display(),
        ))
    })?;
    let next = next_path(exe);
    remove_if_present(&next)?;
    fs::rename(&binary, &next).map_err(|source| CliError::Io {
        path: next.clone(),
        source,
    })?;
    ensure_executable(&next)?;
    remove_dir_if_present(&stage)?;
    write_state(
        exe,
        &UpdateState {
            version: 1,
            drive: drive.to_path_buf(),
            archive_name: identity.canonical_name.clone(),
            archive_version: identity.version.clone(),
            archive_blake3: identity.blake3.clone(),
            phase: Phase::Staged,
        },
    )
}

/// Locate `<top>/bin/wyrd` under the extraction dir: exactly one
/// top-level directory, exactly the documented shape. Anything
/// else is a foreign tarball, not a release archive.
fn find_staged_binary(stage: &Path) -> Option<PathBuf> {
    let mut tops: Vec<PathBuf> = fs::read_dir(stage)
        .ok()?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_dir())
        .collect();
    if tops.len() != 1 {
        return None;
    }
    let candidate = tops.pop()?.join("bin").join("wyrd");
    candidate.is_file().then_some(candidate)
}

#[cfg(unix)]
fn ensure_executable(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|source| CliError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    permissions.set_mode(permissions.mode() | 0o111);
    fs::set_permissions(path, permissions).map_err(|source| CliError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn ensure_executable(_path: &Path) -> Result<(), CliError> {
    Ok(())
}

/// The two swap renames, split so the live transaction records
/// `Swapped` between them (`set_phase`): a crash in either half
/// is what `converge` exists for. The old binary survives by
/// construction — deletion waits for a passed verification.
pub(crate) fn swap_first(exe: &Path) -> Result<(), CliError> {
    let prev = prev_path(exe);
    remove_if_present(&prev)?;
    rename_durable(exe, &prev, exe)?;
    Ok(())
}

pub(crate) fn swap_second(exe: &Path) -> Result<(), CliError> {
    let next = next_path(exe);
    if !next.is_file() {
        return Err(CliError::Usage(format!(
            "{}: no staged binary; stage before swapping",
            next.display()
        )));
    }
    rename_durable(&next, exe, exe)?;
    Ok(())
}

fn set_phase(
    exe: &Path,
    drive: &Path,
    identity: &ArchiveIdentity,
    phase: Phase,
) -> Result<(), CliError> {
    write_state(
        exe,
        &UpdateState {
            version: 1,
            drive: drive.to_path_buf(),
            archive_name: identity.canonical_name.clone(),
            archive_version: identity.version.clone(),
            archive_blake3: identity.blake3.clone(),
            phase,
        },
    )
}

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
        match child
            .try_wait()
            .map_err(|source| CliError::Usage(format!("verification wait failed ({source})")))?
        {
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
    )? {
        VerifyOutcome::Verified => {}
        VerifyOutcome::Rejected => {
            rollback(exe, &identity.canonical_name)?;
            println!("update rollback: restored {own}");
            record_verdict(
                exe,
                &UpdateVerdict {
                    version: 1,
                    outcome: "rolled-back".into(),
                    drive: drive_dir.to_path_buf(),
                    new_version: identity.version.clone(),
                    in_place: own.clone(),
                    at: now_unix(),
                },
            );
            if *restart {
                // Rollback with continuity: the drive must not sit
                // unserved with nothing started — hand the restored
                // binary to supervision. The refusal is carried by
                // the `update rollback:` line above (exit status
                // reports the supervised run, §6).
                println!("update continuity: supervising restored {own} as the vault child");
                return Ok(supervise_outcome(
                    exe,
                    drive_dir,
                    relays,
                    identity_file,
                    passphrase_file,
                ));
            }
            return Err(CliError::Verification(format!(
                "new build {} did not verify the drive; restored {own}",
                identity.version
            )));
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
fn record_verdict(exe: &Path, verdict: &UpdateVerdict) {
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

fn now_unix() -> u64 {
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

/// Advisory preflight against the staged binary: run its
/// lock-free self-report and compare with this build's. A staged
/// binary that cannot report is broken — refuse before the swap.
/// Anything it reports is advisory per [`preflight_report`]: the
/// lines print, and the transaction proceeds.
pub(crate) fn run_preflight(next: &Path) -> Result<(), CliError> {
    let output = std::process::Command::new(next)
        .arg("__build_info")
        .output()
        .map_err(|source| {
            CliError::Usage(format!(
                "staged binary failed to execute ({source}); refusing the swap"
            ))
        })?;
    if !output.status.success() {
        return Err(CliError::Usage(
            "staged binary refused its self-report; refusing the swap".to_string(),
        ));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let staged = parse_build_info(&text).ok_or_else(|| {
        CliError::Usage(format!(
            "staged binary reported unparsable versions ({text:?}); refusing the swap"
        ))
    })?;
    for line in preflight_report(&own_build_info(), &staged) {
        println!("{line}");
    }
    Ok(())
}

/// A binary's lock-free self-report for the advisory preflight
/// (U2-A): compiled format versions, comparable without opening
/// any store. `__build_info` prints exactly these lines; the
/// preflight compares them across the running and staged builds.
pub(crate) struct BuildInfo {
    pub app: String,
    pub envelope: u8,
    pub control: u8,
}

pub(crate) fn own_build_info() -> BuildInfo {
    BuildInfo {
        app: env!("CARGO_PKG_VERSION").to_owned(),
        envelope: ENVELOPE_VERSION,
        control: CONTROL_VERSION,
    }
}

pub(crate) fn render_build_info(info: &BuildInfo) -> String {
    format!(
        "update build: {}\nupdate envelope: 0x{:02x}\nupdate control: 0x{:02x}",
        info.app, info.envelope, info.control
    )
}

/// Parse the three lines `__build_info` prints. `None` means the
/// staged binary is broken — itself a refusal, since a binary that
/// cannot report its versions cannot be verified either.
pub(crate) fn parse_build_info(output: &str) -> Option<BuildInfo> {
    let mut lines = output.lines();
    let app = lines.next()?.strip_prefix("update build: ")?.to_owned();
    let envelope =
        u8::from_str_radix(lines.next()?.strip_prefix("update envelope: 0x")?, 16).ok()?;
    let control = u8::from_str_radix(lines.next()?.strip_prefix("update control: 0x")?, 16).ok()?;
    if app.is_empty() {
        return None;
    }
    Some(BuildInfo {
        app,
        envelope,
        control,
    })
}

/// Numeric-prefix app-version ordering for the downgrade warning:
/// compare leading `major.minor.patch` numerically, ignore the
/// prerelease tail. Unparsable versions compare equal — no warning
/// on what cannot be ordered.
fn app_version_older(staged: &str, current: &str) -> bool {
    fn numeric(prefix: &str) -> Vec<u64> {
        prefix
            .split(['.', '-'])
            .take_while(|part| part.bytes().all(|b| b.is_ascii_digit()))
            .filter_map(|part| part.parse().ok())
            .collect()
    }
    let (mut a, mut b) = (numeric(staged), numeric(current));
    a.resize(3, 0);
    b.resize(3, 0);
    a < b
}

/// The advisory preflight: compare the staged binary's self-report
/// against this build's. Today's format versions are single values
/// with no minimum-readable concept, so no version inequality is
/// structurally impossible — the report is printed and the
/// transaction proceeds, except for a downgrade, which warns
/// (older alphas may not read stores newer ones wrote; the
/// verification in the gap decides). Advisory means exactly this:
/// cheap, lock-free, and never the load-bearing check.
pub(crate) fn preflight_report(own: &BuildInfo, staged: &BuildInfo) -> Vec<String> {
    let mut lines = vec![
        format!("update preflight: staged build {}", staged.app),
        format!(
            "update preflight: envelope 0x{:02x} -> 0x{:02x}, control 0x{:02x} -> 0x{:02x}",
            own.envelope, staged.envelope, own.control, staged.control
        ),
    ];
    if app_version_older(&staged.app, &own.app) {
        lines.push(format!(
            "update preflight: warning: staged {} is older than running {}; verification decides",
            staged.app, own.app
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_harness::TempDir;

    fn write_archive(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = fs::File::create(&path).unwrap();
        file.write_all(bytes).unwrap();
        path
    }

    /// A canonically-named archive for THIS host: the host check in
    /// `resolve_archive` refuses foreign platforms, so tests that
    /// resolve must name the platform they run on.
    fn host_archive_name(version: &str) -> String {
        let (os, arch) = host_platform();
        format!(
            "wyrd-{version}-{}-{}.tar.gz",
            os.unwrap_or("linux"),
            arch.unwrap_or("aarch64")
        )
    }

    /// A canonically-named archive for a FOREIGN platform: always
    /// refused by the host check, on every host that can judge.
    fn foreign_archive_name(version: &str) -> String {
        let (os, _) = host_platform();
        let foreign_os = match os {
            Some("macos") => "linux",
            _ => "macos",
        };
        format!("wyrd-{version}-{foreign_os}-aarch64.tar.gz")
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
        let name = host_archive_name("0.3.0-alpha");
        let path = write_archive(&temp.0, &name, b"fake-archive");
        let identity = resolve_archive(&path).unwrap();
        assert_eq!(identity.canonical_name, name);
        assert_eq!(identity.version, "0.3.0-alpha");
        assert_eq!(identity.bytes, b"fake-archive".len() as u64);
        assert_eq!(
            identity.blake3,
            blake3::hash(b"fake-archive").to_hex().to_string()
        );
    }

    #[test]
    fn resolve_refuses_a_foreign_platform_with_both_named() {
        let temp = TempDir::new();
        let name = foreign_archive_name("0.3.0-alpha");
        let path = write_archive(&temp.0, &name, b"fake-archive");
        let error = resolve_archive(&path).unwrap_err();
        let message = error.to_string();
        // On a judgable host the message names both platforms;
        // elsewhere the archive resolves (the preflight backstops).
        if host_platform().0.is_some() {
            assert!(message.contains("this host is"), "{message}");
            assert!(message.contains(&name), "{message}");
        }
    }

    #[test]
    fn resolve_allows_the_rosetta_pair_only() {
        // The release script runs cross-arch macOS binaries under
        // Rosetta, so the host check allows exactly that pair
        // alongside the native one. Only meaningful on
        // Apple silicon; elsewhere the foreign test covers
        // refusal and the host-name test covers acceptance.
        if host_platform() != (Some("macos"), Some("aarch64")) {
            return;
        }
        let temp = TempDir::new();
        let rosetta = write_archive(&temp.0, "wyrd-0.4.0-alpha-macos-x86_64.tar.gz", b"x");
        assert_eq!(resolve_archive(&rosetta).unwrap().arch, "x86_64");
        let foreign = write_archive(&temp.0, "wyrd-0.4.0-alpha-linux-aarch64.tar.gz", b"x");
        assert!(resolve_archive(&foreign).is_err());
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
    fn incompatible_report_names_the_invariant_and_the_gaps() {
        let report = render_compatibility(&CompatibilityStatus::Incompatible {
            invariant: 10,
            detail: "unknown envelope version 0x7f".into(),
        });
        assert!(
            report.starts_with(
                "update compatibility: incompatible (invariant 10: unknown envelope version 0x7f)"
            ),
            "{report}"
        );
        for gap in UNVERIFIED_GAPS {
            assert!(report.contains(&format!("update gap: {gap}")), "{report}");
        }
    }

    #[test]
    fn verified_report_carries_the_gaps_too() {
        // OD-U4 option A over option B: a green verdict that omits
        // the blocked invariants is a defect, not a simplification.
        let report = render_compatibility(&CompatibilityStatus::Verified {
            checks: vec!["store opens under this build".into()],
        });
        assert!(
            report.contains("update compatibility: verified (1 check)"),
            "{report}"
        );
        assert!(
            report.contains("update check: store opens under this build"),
            "{report}"
        );
        for gap in UNVERIFIED_GAPS {
            assert!(report.contains(&format!("update gap: {gap}")), "{report}");
        }
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

    #[test]
    fn build_info_round_trips_through_its_own_lines() {
        let info = BuildInfo {
            app: "0.3.0-alpha".into(),
            envelope: 0x00,
            control: 0x02,
        };
        let parsed = parse_build_info(&render_build_info(&info)).unwrap();
        assert_eq!(parsed.app, "0.3.0-alpha");
        assert_eq!(parsed.envelope, 0x00);
        assert_eq!(parsed.control, 0x02);
        for broken in [
            "",
            "update build: \nupdate envelope: 0x00\nupdate control: 0x00",
            "garbage",
        ] {
            assert!(parse_build_info(broken).is_none(), "{broken:?}");
        }
    }

    #[test]
    fn preflight_reports_versions_and_warns_on_downgrade_only() {
        let own = BuildInfo {
            app: "0.3.0-alpha".into(),
            envelope: 0x00,
            control: 0x00,
        };
        let same = preflight_report(&own, &own);
        assert_eq!(same.len(), 2);
        assert!(
            same.iter().all(|line| !line.contains("warning")),
            "{same:?}"
        );
        let newer = BuildInfo {
            app: "0.4.0-alpha".into(),
            envelope: 0x01,
            control: 0x00,
        };
        let upgrade = preflight_report(&own, &newer);
        assert!(
            upgrade.iter().any(|line| line.contains("0x00 -> 0x01")),
            "{upgrade:?}"
        );
        assert!(
            upgrade.iter().all(|line| !line.contains("warning")),
            "{upgrade:?}"
        );
        let older = BuildInfo {
            app: "0.2.0-alpha".into(),
            envelope: 0x00,
            control: 0x00,
        };
        let downgrade = preflight_report(&own, &older);
        assert!(
            downgrade.iter().any(|line| line.contains("warning")),
            "{downgrade:?}"
        );
        // Numeric, not lexicographic: 0.10 is newer than 0.9.
        assert!(!app_version_older("0.10.0", "0.9.0"));
        assert!(app_version_older("0.9.0", "0.10.0"));
    }

    fn fake_exe(dir: &Path) -> PathBuf {
        let exe = dir.join("wyrd");
        fs::write(&exe, b"old-binary").unwrap();
        exe
    }

    fn record(exe: &Path, phase: Phase) {
        write_state(
            exe,
            &UpdateState {
                version: 1,
                drive: PathBuf::from("/srv/drive"),
                archive_name: "wyrd-0.4.0-alpha-linux-aarch64.tar.gz".into(),
                archive_version: "0.4.0-alpha".into(),
                archive_blake3: "ab".into(),
                phase,
            },
        )
        .unwrap();
    }

    #[test]
    fn converge_is_clean_with_no_record() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        assert_eq!(converge(&exe).unwrap(), Converged::Clean);
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
    }

    #[test]
    fn converge_staged_drops_staging_and_keeps_the_binary() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::write(next_path(&exe), b"staged").unwrap();
        record(&exe, Phase::Staged);
        match converge(&exe).unwrap() {
            Converged::RolledBack(reason) => assert!(reason.contains("unstaged"), "{reason}"),
            other => panic!("staged must roll back, got: {other:?}"),
        }
        assert!(!next_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
    }

    #[test]
    fn converge_swapped_restores_the_old_binary() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::write(&exe, b"new-binary").unwrap();
        fs::write(prev_path(&exe), b"old-binary").unwrap();
        record(&exe, Phase::Swapped);
        match converge(&exe).unwrap() {
            Converged::RolledBack(reason) => assert!(reason.contains("restored"), "{reason}"),
            other => panic!("swapped must restore, got: {other:?}"),
        }
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
    }

    #[test]
    fn converge_crash_between_renames_still_unwinds() {
        // Crash after exe->prev but before next->exe: the
        // executable is missing, prev and next both present.
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::rename(&exe, prev_path(&exe)).unwrap();
        fs::write(next_path(&exe), b"new-binary").unwrap();
        record(&exe, Phase::Swapped);
        assert!(matches!(converge(&exe).unwrap(), Converged::RolledBack(_)));
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!state_path(&exe).exists());
    }

    #[test]
    fn converge_swapped_without_prev_names_manual_recovery() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        record(&exe, Phase::Swapped);
        let error = converge(&exe).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("reinstall"), "{message}");
        assert!(message.contains(".update-state"), "{message}");
    }

    #[test]
    fn converge_verified_completes_the_commit() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::write(&exe, b"new-binary").unwrap();
        fs::write(prev_path(&exe), b"old-binary").unwrap();
        record(&exe, Phase::Verified);
        assert_eq!(
            converge(&exe).unwrap(),
            Converged::Committed("0.4.0-alpha".into())
        );
        assert_eq!(fs::read(&exe).unwrap(), b"new-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
    }

    fn make_tarball(dir: &Path, name: &str, payload: &[u8]) -> PathBuf {
        let top = dir.join("top");
        fs::create_dir_all(top.join("bin")).unwrap();
        fs::write(top.join("bin").join("wyrd"), payload).unwrap();
        let archive = dir.join(name);
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(dir)
            .arg("top")
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(&top).unwrap();
        archive
    }

    fn test_identity(name: &str, version: &str) -> ArchiveIdentity {
        ArchiveIdentity {
            canonical_name: name.to_owned(),
            version: version.to_owned(),
            os: "linux".into(),
            arch: "aarch64".into(),
            blake3: "ab".into(),
            bytes: 0,
        }
    }

    /// Credential paths the parent forwards without reading: real
    /// files (the child would open them), owned by this test's
    /// directory so no two tests share a path.
    fn forward_creds(dir: &Path) -> (PathBuf, PathBuf) {
        let identity = dir.join("fwd-identity");
        let passphrase = dir.join("fwd-passphrase");
        fs::write(&identity, b"forwarded").unwrap();
        fs::write(&passphrase, b"forwarded").unwrap();
        (identity, passphrase)
    }

    /// A drive-shaped directory for transaction tests: the shape
    /// check requires a `keystore` or `LOCK` name, and an empty
    /// `LOCK` is what a pre-first-open drive looks like before
    /// the probe creates one.
    fn fake_drive(dir: &Path) -> PathBuf {
        let drive = dir.join("drive");
        fs::create_dir_all(&drive).unwrap();
        fs::write(drive.join("LOCK"), b"").unwrap();
        drive
    }

    #[test]
    fn check_drive_dir_refuses_non_drives() {
        let temp = TempDir::new();
        assert!(matches!(
            check_drive_dir(&temp.0.join("absent")).unwrap_err(),
            CliError::Io { .. }
        ));
        let empty = temp.0.join("empty");
        fs::create_dir_all(&empty).unwrap();
        let error = check_drive_dir(&empty).unwrap_err();
        assert!(
            error.to_string().contains("not a drive directory"),
            "{error}"
        );
        let drive = fake_drive(&temp.0);
        check_drive_dir(&drive).unwrap();
    }

    fn update_request<'a>(
        drive: &'a Path,
        archive: &'a Path,
        creds: &'a (PathBuf, PathBuf),
        relays: &'a [String],
        restart: bool,
        exe: &'a Path,
    ) -> UpdateRequest<'a> {
        UpdateRequest {
            drive_dir: drive,
            archive,
            identity_file: &creds.0,
            passphrase_file: &creds.1,
            relays,
            restart,
            exe,
        }
    }

    #[test]
    #[cfg(unix)]
    fn stage_extracts_top_bin_wyrd_and_records() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let name = host_archive_name("0.4.0-alpha");
        let archive = make_tarball(&temp.0, &name, b"new-binary");
        let identity = test_identity(&name, "0.4.0-alpha");
        stage_archive(&exe, Path::new("/srv/drive"), &archive, &identity).unwrap();
        assert_eq!(fs::read(next_path(&exe)).unwrap(), b"new-binary");
        assert_eq!(read_state(&exe).unwrap().unwrap().phase, Phase::Staged);
    }

    #[test]
    fn stage_rejects_a_foreign_tarball_with_no_record() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let name = host_archive_name("0.4.0-alpha");
        let archive = temp.0.join(&name);
        fs::write(&archive, b"not a tarball").unwrap();
        let identity = test_identity(&name, "0.4.0-alpha");
        let error = stage_archive(&exe, Path::new("/srv/drive"), &archive, &identity).unwrap_err();
        assert!(error.to_string().contains("unpackable"), "{error}");
        assert!(read_state(&exe).unwrap().is_none());
        assert!(!next_path(&exe).exists());
    }

    #[test]
    fn swap_moves_old_aside_and_staged_into_place() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::write(next_path(&exe), b"new-binary").unwrap();
        swap_first(&exe).unwrap();
        // Between the renames the executable is missing: exactly
        // the window converge unwinds.
        assert!(!exe.exists());
        swap_second(&exe).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new-binary");
        assert_eq!(fs::read(prev_path(&exe)).unwrap(), b"old-binary");
    }

    #[test]
    fn swap_refuses_without_a_staged_binary() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        swap_first(&exe).unwrap();
        let error = swap_second(&exe).unwrap_err();
        assert!(error.to_string().contains("no staged binary"), "{error}");
        // First rename already moved old aside: converge would
        // restore it; the test cleans up by hand.
        fs::rename(prev_path(&exe), &exe).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
    }

    #[test]
    fn converge_staged_with_missing_exe_restores_first() {
        // Crash after the first rename but before the Swapped
        // record: the phase still reads Staged, yet the
        // executable is gone. The unwind prefix restores prev
        // before the phase cleanup runs.
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        fs::rename(&exe, prev_path(&exe)).unwrap();
        fs::write(next_path(&exe), b"new-binary").unwrap();
        record(&exe, Phase::Staged);
        assert!(matches!(converge(&exe).unwrap(), Converged::RolledBack(_)));
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!state_path(&exe).exists());
    }

    #[test]
    #[cfg(unix)]
    fn preflight_runs_the_staged_self_report() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new();
        let script = temp.0.join("wyrd.next");
        fs::write(
            &script,
            "#!/bin/sh\nprintf 'update build: 0.4.0-alpha\\nupdate envelope: 0x00\\nupdate control: 0x00\\n'",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        run_preflight(&script).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn preflight_refuses_a_broken_staged_binary() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new();
        let script = temp.0.join("wyrd.next");
        fs::write(&script, "#!/bin/sh\nexit 3\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let error = run_preflight(&script).unwrap_err();
        assert!(error.to_string().contains("refusing the swap"), "{error}");
    }

    /// A staged binary double: a shell script answering the two
    /// internal subcommands. `verify_exit` decides the
    /// `__update_verify` outcome, so the same double drives the
    /// commit and rollback paths with zero mocks.
    #[cfg(unix)]
    fn script_binary(dir: &Path, verify_exit: u8) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("script-wyrd");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"__build_info\" ]; then\n\
                   printf 'update build: 0.4.0-alpha\\nupdate envelope: 0x00\\nupdate control: 0x00\\n'\n\
                   exit 0\n\
                 fi\n\
                 if [ \"$1\" = \"__update_verify\" ]; then\n\
                   printf 'update compatibility: verified (1 checks)\\nupdate check: script\\n'\n\
                   exit {verify_exit}\n\
                 fi\n\
                 exit 9\n"
            ),
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[cfg(unix)]
    fn script_archive(dir: &Path, script: &Path) -> PathBuf {
        let top = dir.join("top");
        fs::create_dir_all(top.join("bin")).unwrap();
        fs::copy(script, top.join("bin").join("wyrd")).unwrap();
        let archive = dir.join(host_archive_name("0.4.0-alpha"));
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(dir)
            .arg("top")
            .status()
            .unwrap();
        assert!(status.success());
        fs::remove_dir_all(&top).unwrap();
        archive
    }

    /// A staged double that passes its FIRST `__update_verify`
    /// and fails every later one: the mark file lives in the
    /// drive directory (`$2`), so no process-global state leaks
    /// between parallel tests. Drives the post-swap rollback
    /// path — early refusal is the always-fail double's job.
    #[cfg(unix)]
    fn counting_script(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("counting-wyrd");
        fs::write(
            &script,
            "#!/bin/sh\n\
             if [ \"$1\" = \"__build_info\" ]; then\n\
               printf 'update build: 0.4.0-alpha\\nupdate envelope: 0x00\\nupdate control: 0x00\\n'\n\
               exit 0\n\
             fi\n\
             if [ \"$1\" = \"__update_verify\" ]; then\n\
               printf 'update compatibility: verified (1 checks)\\nupdate check: script\\n'\n\
               if [ -f \"$2/.update-test-mark\" ]; then exit 3; fi\n\
               touch \"$2/.update-test-mark\"\n\
               exit 0\n\
             fi\n\
             exit 9\n",
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    #[test]
    #[cfg(unix)]
    fn update_run_commits_a_verified_swap() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = script_binary(&temp.0, 0);
        let archive = script_archive(&temp.0, &script);
        let script_bytes = fs::read(&script).unwrap();
        let outcome =
            update_run(&update_request(&drive, &archive, &creds, &[], false, &exe)).unwrap();
        assert_eq!(outcome, UpdateOutcome::Done);
        // The staged script is the binary in place; the rollback
        // copy and the record are gone — rollback impossible.
        assert_eq!(fs::read(&exe).unwrap(), script_bytes);
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        assert!(!next_path(&exe).exists());
        // The durable verdict names the commit for automation
        // that never saw stdout.
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "done");
        assert_eq!(verdict.new_version, "0.4.0-alpha");
        assert_eq!(verdict.in_place, "0.4.0-alpha");
        assert_eq!(verdict.drive, drive);
    }

    #[test]
    #[cfg(unix)]
    fn update_run_refuses_before_any_swap() {
        // Early refusal: the staged double rejects the drive, so
        // the transaction stops with staging rolled back — the
        // executable untouched, no rollback copy, no record. The
        // wording is "did not verify", never "rejected": the
        // child reports exit status only, so an operational
        // failure lands in the same arm as a genuine
        // incompatibility and must not be misattributed.
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = script_binary(&temp.0, 3);
        let archive = script_archive(&temp.0, &script);
        let error =
            update_run(&update_request(&drive, &archive, &creds, &[], false, &exe)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("before any swap"), "{message}");
        assert!(message.contains("did not verify"), "{message}");
        assert!(!message.contains("rejected the drive"), "{message}");
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        assert!(!next_path(&exe).exists());
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "refused");
        assert_eq!(verdict.in_place, own_build_info().app);
    }

    #[test]
    #[cfg(unix)]
    fn update_run_early_refusal_under_restart_supervises_unchanged() {
        // Finding 9 symmetry: under `--restart` the early refusal
        // also hands back to supervision — the binary unchanged,
        // the vault stopped, the drive must not sit unserved. The
        // refusal is carried by the printed `update refused:` line
        // (exit status reports the supervised run, §6).
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = script_binary(&temp.0, 3);
        let archive = script_archive(&temp.0, &script);
        let relays = vec!["ws://localhost:9".to_owned()];
        let outcome = update_run(&update_request(
            &drive, &archive, &creds, &relays, true, &exe,
        ))
        .unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        match outcome {
            UpdateOutcome::Supervise {
                exe: supervised, ..
            } => assert_eq!(supervised, exe),
            UpdateOutcome::Done => panic!("early refusal under restart must supervise, got Done"),
        }
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "refused");
    }

    #[test]
    #[cfg(unix)]
    fn update_run_rolls_back_a_post_swap_rejection() {
        // The counting double passes early and fails authoritative:
        // the swap happened, so rollback restores the old binary.
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = counting_script(&temp.0);
        let archive = script_archive(&temp.0, &script);
        let error =
            update_run(&update_request(&drive, &archive, &creds, &[], false, &exe)).unwrap_err();
        assert!(
            matches!(&error, CliError::Verification(message) if message.contains("did not verify the drive")),
            "post-swap rejection must name the drive, got: {error}"
        );
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "rolled-back");
        assert_eq!(verdict.new_version, "0.4.0-alpha");
        assert_eq!(verdict.in_place, own_build_info().app);
    }

    #[test]
    #[cfg(unix)]
    fn update_run_rejection_under_restart_supervises_the_restored_binary() {
        // Rollback with continuity: after a post-swap rejection
        // under `--restart`, the transaction hands the RESTORED
        // binary to supervision instead of returning — the drive
        // must not sit unserved with nothing started.
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = counting_script(&temp.0);
        let archive = script_archive(&temp.0, &script);
        let relays = vec!["ws://localhost:9".to_owned()];
        let outcome = update_run(&update_request(
            &drive, &archive, &creds, &relays, true, &exe,
        ))
        .unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"old-binary");
        assert!(!prev_path(&exe).exists());
        assert!(!state_path(&exe).exists());
        match outcome {
            UpdateOutcome::Supervise {
                exe: supervised,
                drive: supervised_drive,
                relays: supervised_relays,
                ..
            } => {
                assert_eq!(supervised, exe);
                assert_eq!(supervised_drive, drive);
                assert_eq!(supervised_relays, relays);
            }
            UpdateOutcome::Done => panic!("restart rejection must supervise, got Done"),
        }
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "rolled-back");
    }

    #[test]
    #[cfg(unix)]
    fn update_run_commit_under_restart_supervises_the_new_binary() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        let drive = fake_drive(&temp.0);
        let creds = forward_creds(&temp.0);
        let script = script_binary(&temp.0, 0);
        let archive = script_archive(&temp.0, &script);
        let script_bytes = fs::read(&script).unwrap();
        let relays = vec!["ws://localhost:9".to_owned()];
        let outcome = update_run(&update_request(
            &drive, &archive, &creds, &relays, true, &exe,
        ))
        .unwrap();
        assert_eq!(fs::read(&exe).unwrap(), script_bytes);
        match outcome {
            UpdateOutcome::Supervise {
                exe: supervised, ..
            } => assert_eq!(supervised, exe),
            UpdateOutcome::Done => panic!("restart commit must supervise, got Done"),
        }
        let verdict = read_verdict(&exe).unwrap().expect("verdict recorded");
        assert_eq!(verdict.outcome, "done");
    }

    #[test]
    fn vault_command_names_the_hand_run_argv() {
        let command = vault_command(
            Path::new("/opt/wyrd"),
            Path::new("/srv/drive"),
            &["ws://localhost:9".to_owned()],
            Path::new("/srv/id"),
            Path::new("/srv/pp"),
        );
        assert_eq!(command.get_program(), Path::new("/opt/wyrd"));
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "vault",
                "/srv/drive",
                "--relay",
                "ws://localhost:9",
                "--identity-file",
                "/srv/id",
                "--passphrase-file",
                "/srv/pp",
            ]
        );
    }

    #[test]
    #[cfg(unix)]
    fn verify_child_timeout_is_an_operational_rollback() {
        let temp = TempDir::new();
        let script = temp.0.join("hang");
        fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let creds = forward_creds(&temp.0);
        let error = run_verify_child(
            &script,
            Path::new("/srv/drive"),
            &creds.0,
            &creds.1,
            Duration::from_secs(1),
        )
        .unwrap_err();
        // A timeout never claims incompatibility: usage error, no
        // verdict — the caller rolls back on it like any
        // unverified outcome.
        assert!(
            matches!(&error, CliError::Usage(message) if message.contains("timed out")),
            "timeout must be operational, got: {error}"
        );
    }

    fn verdict_fixture(outcome: &str) -> UpdateVerdict {
        UpdateVerdict {
            version: 1,
            outcome: outcome.into(),
            drive: PathBuf::from("/srv/drive"),
            new_version: "0.4.0-alpha".into(),
            in_place: "0.3.0-alpha".into(),
            at: 1791792811,
        }
    }

    #[test]
    fn verdict_round_trips_with_its_shape() {
        let temp = TempDir::new();
        let exe = fake_exe(&temp.0);
        assert!(read_verdict(&exe).unwrap().is_none());
        write_verdict(&exe, &verdict_fixture("in_progress")).unwrap();
        assert_eq!(
            read_verdict(&exe).unwrap().unwrap(),
            verdict_fixture("in_progress")
        );
        // Each run overwrites: the terminal outcome replaces the
        // start marker, so the file always names the latest
        // reached phase.
        write_verdict(&exe, &verdict_fixture("done")).unwrap();
        assert_eq!(read_verdict(&exe).unwrap().unwrap().outcome, "done");
    }

    #[test]
    fn verdict_write_failure_warns_and_continues() {
        // The record is a channel, not a transaction step: an
        // unwritable location must never fail the run. A path
        // nested under a regular file fails for every uid —
        // permission bits would not fail root, and CI runs as
        // root — so this is ENOTDIR, not EACCES.
        let temp = TempDir::new();
        let anchor = temp.0.join("anchor");
        fs::write(&anchor, b"not a directory").unwrap();
        let exe = anchor.join("wyrd");
        assert!(write_verdict(&exe, &verdict_fixture("done")).is_err());
        record_verdict(&exe, &verdict_fixture("done"));
    }

    #[test]
    fn host_check_derives_from_consts_on_every_platform() {
        // The Rosetta allowance is one pair; everything else
        // cross-anything refuses. Derived from the running
        // consts so both axes have coverage on every CI host,
        // not just Apple silicon.
        let (os, arch) = host_platform();
        let Some((os, arch)) = os.zip(arch) else {
            return;
        };
        let temp = TempDir::new();
        // Same-OS other-arch: allowed only as the Rosetta pair.
        let other_arch = if arch == "aarch64" {
            "x86_64"
        } else {
            "aarch64"
        };
        let name = format!("wyrd-0.4.0-alpha-{os}-{other_arch}.tar.gz");
        let path = write_archive(&temp.0, &name, b"x");
        let rosetta = os == "macos" && arch == "aarch64" && other_arch == "x86_64";
        assert_eq!(resolve_archive(&path).is_ok(), rosetta, "{name}");
        // Other-OS always refuses, same arch or not.
        let other_os = if os == "macos" { "linux" } else { "macos" };
        for name in [
            format!("wyrd-0.4.0-alpha-{other_os}-{arch}.tar.gz"),
            format!("wyrd-0.4.0-alpha-{other_os}-{other_arch}.tar.gz"),
        ] {
            let path = write_archive(&temp.0, &name, b"x");
            assert!(resolve_archive(&path).is_err(), "{name}");
        }
    }
}
