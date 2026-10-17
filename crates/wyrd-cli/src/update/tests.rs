use super::identity::*;
use super::snapshot::*;
use super::state::*;
use super::*;
use crate::tests_harness::TempDir;
use crate::CliError;
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wyrd_sync::control::ControlError;
use wyrd_sync::durable::DurableError;
use wyrd_sync::runtime::EngineError;

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
    let outcome = update_run(&update_request(&drive, &archive, &creds, &[], false, &exe)).unwrap();
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
