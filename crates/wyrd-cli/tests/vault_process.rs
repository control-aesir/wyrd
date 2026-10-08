//! The vault process (issue `22a`): a foreground `wyrd vault`
//! against a real in-process relay reports ready once, serves until
//! SIGINT/SIGTERM, and exits 0 on a clean stop — with the empty
//! fixture's outbox still empty after. Process-level
//! on purpose: readiness, signal handling, and the exit code live in
//! the binary composer, not the library.
//!
//! Unix-only: signals and credential-file hardening are Unix paths,
//! as in production.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// A real relay beside the binary under test: rust-nostr's
/// in-process `LocalRelay` on its own runtime, which this struct owns
/// so the listener outlives every `block_on` (the cross-impl pattern
/// in `wyrd-core`'s mailbox tests).
struct TestRelay {
    _runtime: tokio::runtime::Runtime,
    relay: nostr_sdk::local_relay::LocalRelay,
    url: String,
}

impl TestRelay {
    fn spawn() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("test runtime");
        let relay = nostr_sdk::local_relay::LocalRelay::new();
        runtime.block_on(relay.run()).expect("test relay serves");
        let url = runtime.block_on(relay.url()).to_string();
        TestRelay {
            _runtime: runtime,
            relay,
            url,
        }
    }

    fn shutdown(&self) {
        self.relay.shutdown();
    }
}

struct Fixture {
    dir: PathBuf,
    drive: PathBuf,
    identity: PathBuf,
    passphrase: PathBuf,
}

impl Fixture {
    fn new(case: &str) -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("wyrd-vault-{case}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let drive = dir.join("drive");
        let identity = dir.join("identity");
        let passphrase = dir.join("passphrase");
        // Test-only identity bytes (uniqueness, not secrecy) plus a
        // UTF-8 passphrase, both owner-only like production
        // credential files.
        let mut secret = [0u8; 32];
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        secret[..4].copy_from_slice(&std::process::id().to_ne_bytes());
        secret[4..12].copy_from_slice(&n.to_ne_bytes());
        secret[12..20].copy_from_slice(&(nanos as u64).to_ne_bytes());
        secret[20..28].copy_from_slice(&((nanos >> 64) as u64).to_ne_bytes());
        secret[28..].copy_from_slice(&std::process::id().to_be_bytes());
        std::fs::write(&identity, secret).unwrap();
        std::fs::write(&passphrase, "vault-test-pass").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&identity, &passphrase] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        Fixture {
            dir,
            drive,
            identity,
            passphrase,
        }
    }

    fn wyrd(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_wyrd"));
        command.args(args);
        command
    }

    fn init(&self) {
        let status = self
            .wyrd(&[
                "init",
                self.drive.to_str().unwrap(),
                "--identity-file",
                self.identity.to_str().unwrap(),
                "--passphrase-file",
                self.passphrase.to_str().unwrap(),
            ])
            .status()
            .expect("wyrd init runs");
        assert!(status.success(), "wyrd init succeeds");
    }

    /// Spawn the vault against `relay`, returning the child once its
    /// stderr carries the ready line: TERM lands on a converged
    /// vault, never on startup. The stderr drain thread stays alive
    /// until the child exits: later observer writes (posture,
    /// transient failures) must never hit a closed pipe, which
    /// `eprintln!` would turn into a loop-thread panic and a
    /// flaky non-zero exit.
    fn spawn_until_ready(
        &self,
        relay: &TestRelay,
        log_file: Option<&std::path::Path>,
    ) -> VaultChild {
        let mut argv = vec![
            "vault",
            self.drive.to_str().unwrap(),
            "--relay",
            &relay.url,
            "--identity-file",
            self.identity.to_str().unwrap(),
            "--passphrase-file",
            self.passphrase.to_str().unwrap(),
        ];
        let log_path;
        if let Some(path) = log_file {
            log_path = path.to_str().unwrap().to_string();
            argv.push("--log-file");
            argv.push(&log_path);
        }
        let mut child = self
            .wyrd(&argv)
            .stderr(Stdio::piped())
            .spawn()
            .expect("wyrd vault spawns");
        let (lines, drain) =
            await_stderr_line(&mut child, "vault ready: serving ", Duration::from_secs(90));
        assert!(
            lines
                .iter()
                .any(|line| line.contains("serving over iroh: ")),
            "the bind line precedes readiness, got: {lines:?}"
        );
        let bind = lines
            .iter()
            .find(|line| line.contains("serving over iroh: "))
            .unwrap();
        let ready = lines
            .iter()
            .find(|line| line.contains("vault ready: serving "))
            .unwrap();
        let bind_id = bind.rsplit(' ').next().unwrap();
        let ready_id = ready.rsplit(' ').next().unwrap();
        assert_eq!(
            bind_id, ready_id,
            "the ready line names the bound endpoint, bind={bind_id} ready={ready_id}"
        );
        VaultChild {
            child,
            drain: Some(drain),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Read the child's stderr until a line contains `needle` (or fail on
/// timeout): faster and less flaky than a fixed sleep, and it fails
/// the test instead of hanging the suite. An early EOF fails
/// immediately with what the process said instead of spinning to the
/// deadline. Returns the lines so far plus a drain thread that owns
/// the pipe until EOF: the caller keeps it alive until `wait`, so no
/// later child write ever hits a closed pipe.
fn await_stderr_line(
    child: &mut Child,
    needle: &str,
    timeout: Duration,
) -> (Vec<String>, std::thread::JoinHandle<()>) {
    let stderr = child.stderr.take().expect("stderr piped");
    let mut lines = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut reader = BufReader::new(stderr);
    loop {
        assert!(
            Instant::now() < deadline,
            "vault never printed {needle:?}; got: {lines:?}"
        );
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("stderr reads");
        assert!(
            n > 0,
            "vault exited before printing {needle:?}; got: {lines:?}"
        );
        let trimmed = line.trim_end().to_string();
        if trimmed.contains(needle) {
            lines.push(trimmed);
            break;
        }
        lines.push(trimmed);
    }
    let drain = std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    (lines, drain)
}

/// A vault child past readiness: the drain thread outlives every
/// observer write, and `wait` reaps both.
struct VaultChild {
    child: Child,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl VaultChild {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn wait(mut self) -> ExitStatus {
        let status = self.child.wait().expect("vault reaps");
        // EOF follows the exit, so the join reaps the drain without
        // hanging; a join failure cannot change the exit verdict.
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        status
    }
}

fn sigterm(child: &VaultChild) {
    // No libc in test scope (the workspace denies unsafe code): the
    // platform `kill` delivers the same SIGTERM the supervisor sends.
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(status.success(), "SIGTERM delivers");
}

/// SIGTERM after readiness exits 0: the loop stopped clean and every
/// transport closed.
#[test]
fn vault_sigterm_after_ready_exits_zero() {
    let fixture = Fixture::new("term");
    fixture.init();
    let relay = TestRelay::spawn();
    let child = fixture.spawn_until_ready(&relay, None);
    sigterm(&child);
    let status: ExitStatus = child.wait();
    relay.shutdown();
    assert!(
        status.success(),
        "SIGTERM after readiness exits 0, got {status:?}"
    );
}

/// The stopped vault leaves no pending outbox: `sync status` after
/// the SIGTERM exit reports zero pending announcements,
/// transitions, and capabilities alike, so the TERM raced nothing
/// mid-discharge. Status can open the drive here that it could never
/// probe while the vault held the store lock.
#[test]
fn vault_outbox_empty_after_clean_stop() {
    let fixture = Fixture::new("outbox");
    fixture.init();
    let relay = TestRelay::spawn();
    let child = fixture.spawn_until_ready(&relay, None);
    sigterm(&child);
    assert!(child.wait().success());
    relay.shutdown();
    let output = fixture
        .wyrd(&[
            "sync",
            fixture.drive.to_str().unwrap(),
            "--identity-file",
            fixture.identity.to_str().unwrap(),
            "--passphrase-file",
            fixture.passphrase.to_str().unwrap(),
            "status",
        ])
        .output()
        .expect("wyrd sync status runs");
    assert!(output.status.success(), "status opens the stopped drive");
    let report = String::from_utf8(output.stdout).expect("status renders text");
    for class in ["announcements", "transitions", "capabilities"] {
        assert!(
            report.contains(&format!("outbox {class}: 0 queued, 0 delivered, 0 pending")),
            "no {class} left pending after a clean stop, got:\n{report}"
        );
    }
}

/// A relay-less vault is refused before touching the drive: the
/// refusal precedes the keystore open, so even an uninitialized
/// drive reports the usage error rather than a store error.
#[test]
fn vault_without_relay_is_refused() {
    let fixture = Fixture::new("norelay");
    let output = fixture
        .wyrd(&[
            "vault",
            fixture.drive.to_str().unwrap(),
            "--identity-file",
            fixture.identity.to_str().unwrap(),
            "--passphrase-file",
            fixture.passphrase.to_str().unwrap(),
        ])
        .output()
        .expect("wyrd vault runs");
    assert!(
        !output.status.success(),
        "a relay-less vault must not start"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr renders text");
    assert!(
        stderr.contains("needs at least one --relay"),
        "the refusal names the missing relay, got: {stderr:?}"
    );
}

/// `--log-file` appends across restarts: the second run's ready line
/// lands beside the first run's record instead of truncating it. A
/// restart must not destroy the previous run's evidence.
#[test]
fn vault_log_file_appends_across_restarts() {
    let fixture = Fixture::new("logfile");
    fixture.init();
    let relay = TestRelay::spawn();
    let log = fixture.dir.join("vault.log");
    let first = fixture.spawn_until_ready(&relay, Some(&log));
    sigterm(&first);
    assert!(first.wait().success());
    let second = fixture.spawn_until_ready(&relay, Some(&log));
    sigterm(&second);
    assert!(second.wait().success());
    relay.shutdown();
    let body = std::fs::read_to_string(&log).expect("log file reads");
    assert_eq!(
        body.matches("vault ready").count(),
        2,
        "both runs recorded readiness in one appended file, got:\n{body}"
    );
}
