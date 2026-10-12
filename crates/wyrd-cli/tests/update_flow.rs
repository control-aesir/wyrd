//! The update transaction against real binaries (issue `29`):
//! resolve, early refusal, swap, authoritative verify, commit or
//! rollback — with the executable under test a copy of this very
//! binary, so the swap exercises real `__update_verify` runs and
//! never touches the built artifact.
//!
//! Unix-only: tarballs, executable bits, and file locks are Unix
//! paths, as in production.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn wyrd() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wyrd"))
}

struct Fixture {
    dir: PathBuf,
    drive: PathBuf,
    identity: PathBuf,
    passphrase: PathBuf,
    exe: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("wyrd-update-{case}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let drive = dir.join("drive");
        let identity = dir.join("identity");
        let passphrase = dir.join("passphrase");
        std::fs::write(&identity, [0x22; 32]).unwrap();
        std::fs::write(&passphrase, b"update-test-pass\n").unwrap();
        std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&passphrase, std::fs::Permissions::from_mode(0o600)).unwrap();
        // The executable under test: a copy of this build, so the
        // transaction's renames never touch the built artifact.
        let exe = dir.join("wyrd");
        std::fs::copy(wyrd(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        Fixture {
            dir,
            drive,
            identity,
            passphrase,
            exe,
        }
    }

    fn init(&self) {
        let status = Command::new(wyrd())
            .arg("init")
            .arg(&self.drive)
            .arg("--identity-file")
            .arg(&self.identity)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .status()
            .unwrap();
        assert!(status.success(), "init must succeed");
    }

    /// A release archive holding this build under its canonical
    /// host name: the staged binary verifies for real.
    fn archive(&self) -> PathBuf {
        let top = self.dir.join("top");
        std::fs::create_dir_all(top.join("bin")).unwrap();
        std::fs::copy(wyrd(), top.join("bin").join("wyrd")).unwrap();
        let os = match std::env::consts::OS {
            "macos" => "macos",
            _ => "linux",
        };
        let name = format!("wyrd-0.4.0-alpha-{os}-{}.tar.gz", std::env::consts::ARCH);
        let archive = self.dir.join(&name);
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&self.dir)
            .arg("top")
            .status()
            .unwrap();
        assert!(status.success(), "tar must pack the archive");
        std::fs::remove_dir_all(&top).unwrap();
        archive
    }

    fn update(&self, archive: &Path) -> std::process::Output {
        Command::new(&self.exe)
            .arg("update")
            .arg(&self.drive)
            .arg("--archive")
            .arg(archive)
            .arg("--identity-file")
            .arg(&self.identity)
            .arg("--passphrase-file")
            .arg(&self.passphrase)
            .output()
            .unwrap()
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self.exe.as_os_str().to_owned();
        name.push(suffix);
        self.exe.with_file_name(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The issue's named test: a drive the new build cannot read stops
/// the upgrade BEFORE any swap — the executable byte-identical,
/// no rollback copy, no staged binary, no record.
#[test]
fn an_incompatible_drive_stops_the_upgrade_before_any_swap() {
    let fix = Fixture::new("early-refusal");
    fix.init();
    // Tear the commit marker: CURRENT must be sequence plus hash,
    // so the staged binary's early verify refuses at decode.
    std::fs::write(fix.drive.join("CURRENT"), b"torn").unwrap();
    let before = std::fs::read(&fix.exe).unwrap();

    let archive = fix.archive();
    let output = fix.update(&archive);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The verdict report prints on stdout; the failure summary
    // prints on stderr via the exit path — assert on both.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        !output.status.success(),
        "torn drive must fail:\n{combined}"
    );
    assert!(
        combined.contains("before any swap"),
        "early refusal must say so:\n{combined}"
    );
    assert!(
        combined.contains("invariant 2"),
        "verdict must name the invariant:\n{combined}"
    );
    assert!(
        combined.contains("update gap: fact-payload replay"),
        "gaps ride every report:\n{combined}"
    );
    // Nothing replaced, nothing staged, nothing recorded.
    assert_eq!(std::fs::read(&fix.exe).unwrap(), before);
    for suffix in [".prev", ".next", ".update-state", ".stage"] {
        assert!(
            !fix.sibling(suffix).exists(),
            "leftover {}",
            fix.sibling(suffix).display()
        );
    }
}

/// A healthy drive upgrades for real: early verify passes, the
/// swap lands, the authoritative verify commits, and the binary
/// in place is the staged build with no residue.
#[test]
fn a_compatible_drive_upgrades_end_to_end() {
    let fix = Fixture::new("happy");
    fix.init();
    let archive = fix.archive();

    let output = fix.update(&archive);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "healthy drive must upgrade:\n{stdout}"
    );
    assert!(
        stdout.contains("update done"),
        "must report the commit:\n{stdout}"
    );
    assert_eq!(
        std::fs::read(&fix.exe).unwrap(),
        std::fs::read(wyrd()).unwrap()
    );
    for suffix in [".prev", ".next", ".update-state", ".stage"] {
        assert!(
            !fix.sibling(suffix).exists(),
            "leftover {}",
            fix.sibling(suffix).display()
        );
    }
    // And the drive still verifies under the swapped-in binary.
    let verify = Command::new(&fix.exe)
        .arg("__update_verify")
        .arg(&fix.drive)
        .arg("--identity-file")
        .arg(&fix.identity)
        .arg("--passphrase-file")
        .arg(&fix.passphrase)
        .output()
        .unwrap();
    let verify_out = String::from_utf8_lossy(&verify.stdout);
    assert!(
        verify.status.success(),
        "swapped binary must verify:\n{verify_out}"
    );
    assert!(
        verify_out.contains("update compatibility: verified"),
        "verdict:\n{verify_out}"
    );
}

/// A held drive refuses before staging: the lock probe fails the
/// transaction fast with `stop it first`, and the installation is
/// untouched.
#[test]
fn a_held_drive_refuses_before_staging() {
    let fix = Fixture::new("held");
    fix.init();
    let before = std::fs::read(&fix.exe).unwrap();
    // Hold the store lock the way a running vault does: an
    // exclusive flock on LOCK from this process contends with
    // the update child's probe across open descriptions.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fix.drive.join("LOCK"))
        .unwrap();
    lock.try_lock().unwrap();

    let archive = fix.archive();
    let output = fix.update(&archive);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "held drive must fail");
    assert!(
        stdout.contains("stop it first") || stderr.contains("stop it first"),
        "must name the refusal:\n{stdout}\n{stderr}"
    );
    assert_eq!(std::fs::read(&fix.exe).unwrap(), before);
    for suffix in [".prev", ".next", ".update-state", ".stage"] {
        assert!(
            !fix.sibling(suffix).exists(),
            "leftover {}",
            fix.sibling(suffix).display()
        );
    }
}
