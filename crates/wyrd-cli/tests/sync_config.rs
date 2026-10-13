//! Persistent relay configuration (issue `27`): a drive directory
//! with a `default.toml` needs no `--relay` on the command line —
//! `sync now` converges over the configured relays, the refusal and
//! `--offline` semantics judge the effective set, and `sync status`
//! plus `cache policy` name where the configuration came from.
//!
//! Process-level on purpose: argument resolution, file reading, and
//! exit codes live in the binary composer, not the library. The
//! relay is rust-nostr's in-process `LocalRelay` on localhost, so
//! these run in the default gate like the vault process tests.
//!
//! Unix-only: signals and credential-file hardening are Unix paths,
//! as in production.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output};

/// A real relay beside the binary under test: rust-nostr's
/// in-process `LocalRelay` on its own runtime, which this struct owns
/// so the listener outlives every `block_on` (the cross-impl pattern
/// in `wyrd-core`'s mailbox tests, shared with `vault_process.rs`).
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
            std::env::temp_dir().join(format!("wyrd-syconf-{case}-{}-{n}", std::process::id()));
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
        std::fs::write(&passphrase, "sync-config-test-pass").unwrap();
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

    fn write_default_toml(&self, text: &str) {
        std::fs::write(self.drive.join("default.toml"), text).expect("config file writes");
    }

    fn cred_args(&self) -> [&str; 4] {
        [
            "--identity-file",
            self.identity.to_str().unwrap(),
            "--passphrase-file",
            self.passphrase.to_str().unwrap(),
        ]
    }

    fn sync_now(&self, extra: &[&str]) -> Output {
        let mut argv = vec!["sync", self.drive.to_str().unwrap()];
        argv.extend(extra.iter().copied());
        argv.extend(self.cred_args());
        argv.push("now");
        self.wyrd(&argv).output().expect("wyrd sync now runs")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A drive directory with a configuration file needs no `--relay`:
/// `sync now` converges over the configured relays and names the
/// file as their source.
#[test]
fn sync_now_reads_relays_from_the_drive_config() {
    let fixture = Fixture::new("file-relays");
    fixture.init();
    let relay = TestRelay::spawn();
    fixture.write_default_toml(&format!("[drive]\nrelays = [\"{}\"]\n", relay.url));
    let output = fixture.sync_now(&[]);
    let stdout = String::from_utf8(output.stdout).expect("stdout renders text");
    relay.shutdown();
    assert!(
        output.status.success(),
        "sync now converges over configured relays, got:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "relays from: config file ({})",
            fixture.drive.join("default.toml").display()
        )),
        "the summary names the file as the relay source, got:\n{stdout}"
    );
}

/// The empty-means-idle refusal is preserved, not weakened: a file
/// that declares no relays still refuses a bare `sync now`, and the
/// refusal names the file alongside the opt-out.
#[test]
fn an_empty_configured_relay_list_still_refuses_a_bare_sync_now() {
    let fixture = Fixture::new("empty-relays");
    fixture.init();
    fixture.write_default_toml("[drive]\nrelays = []\n");
    let output = fixture.sync_now(&[]);
    assert!(!output.status.success(), "a relay-less run must not exit 0");
    let stderr = String::from_utf8(output.stderr).expect("stderr renders text");
    assert!(
        stderr.contains("no relays in")
            && stderr.contains("default.toml")
            && stderr.contains("--offline"),
        "the refusal names the file and the opt-out, got: {stderr:?}"
    );
}

/// A configured relay contradicts `--offline` exactly like a flag:
/// the combination is refused before the keystore opens, naming the
/// file so the operator knows which surface to change.
#[test]
fn offline_with_configured_relays_is_refused_naming_the_file() {
    let fixture = Fixture::new("offline-conflict");
    fixture.init();
    let relay = TestRelay::spawn();
    fixture.write_default_toml(&format!("[drive]\nrelays = [\"{}\"]\n", relay.url));
    // --offline belongs to `now`, after the action and the
    // credential flags.
    let mut argv = vec!["sync", fixture.drive.to_str().unwrap()];
    argv.extend(fixture.cred_args());
    argv.extend(["now", "--offline"]);
    let output = fixture.wyrd(&argv).output().expect("wyrd sync now runs");
    relay.shutdown();
    assert!(
        !output.status.success(),
        "--offline with configured relays must not run"
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr renders text");
    assert!(
        stderr.contains("--offline") && stderr.contains("default.toml"),
        "the refusal names the pair, got: {stderr:?}"
    );
}

/// Explicit `--relay` flags replace the configured list: the run
/// converges over the flag relays and the provenance says flags,
/// even with a file present.
#[test]
fn relay_flags_replace_the_configured_list() {
    let fixture = Fixture::new("flag-wins");
    fixture.init();
    let relay = TestRelay::spawn();
    // A dead file entry: under append semantics this would linger
    // in the effective set; under replace semantics the flags rule.
    fixture.write_default_toml("[drive]\nrelays = [\"ws://127.0.0.1:9\"]\n");
    let mut argv = vec![
        "sync",
        fixture.drive.to_str().unwrap(),
        "--relay",
        &relay.url,
    ];
    argv.extend(fixture.cred_args());
    argv.push("now");
    let output = fixture.wyrd(&argv).output().expect("wyrd sync now runs");
    let stdout = String::from_utf8(output.stdout).expect("stdout renders text");
    relay.shutdown();
    assert!(
        output.status.success(),
        "flag relays carry the run, got:\n{stdout}"
    );
    assert!(
        stdout.contains("relays from: command-line flags"),
        "the summary names flags as the source, got:\n{stdout}"
    );
}

/// `sync status` never connects, but it still names where its relay
/// count came from: the file, with its path.
#[test]
fn sync_status_names_the_config_file() {
    let fixture = Fixture::new("status-source");
    fixture.init();
    let relay = TestRelay::spawn();
    fixture.write_default_toml(&format!("[drive]\nrelays = [\"{}\"]\n", relay.url));
    relay.shutdown();
    let mut argv = vec!["sync", fixture.drive.to_str().unwrap()];
    argv.extend(fixture.cred_args());
    argv.push("status");
    let output = fixture.wyrd(&argv).output().expect("wyrd sync status runs");
    assert!(output.status.success(), "status observes the drive");
    let stdout = String::from_utf8(output.stdout).expect("stdout renders text");
    assert!(
        stdout.contains("mailbox: 1 relays configured")
            && stdout.contains(&format!(
                "relays from: config file ({})",
                fixture.drive.join("default.toml").display()
            )),
        "status counts the configured relay and names the file, got:\n{stdout}"
    );
}

/// `cache policy` reports the effective configuration: the file it
/// read, the relay source, and which surface each credential path
/// came from — here the file for all three, with no credential
/// flags passed at all.
#[test]
fn cache_policy_reports_the_effective_configuration() {
    let fixture = Fixture::new("policy-source");
    fixture.init();
    let relay = TestRelay::spawn();
    let url = relay.url.clone();
    relay.shutdown();
    fixture.write_default_toml(&format!(
        "[drive]\nrelays = [\"{url}\"]\nidentity_file = \"{}\"\npassphrase_file = \"{}\"\n",
        fixture.identity.display(),
        fixture.passphrase.display(),
    ));
    let output = fixture
        .wyrd(&["cache", fixture.drive.to_str().unwrap(), "policy"])
        .output()
        .expect("wyrd cache policy runs");
    assert!(
        output.status.success(),
        "policy resolves credentials from the file"
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout renders text");
    for line in [
        format!("  file: {}", fixture.drive.join("default.toml").display()),
        "  relays: 1 (config file)".to_string(),
        "  identity_file: config file".to_string(),
        "  passphrase_file: config file".to_string(),
    ] {
        assert!(
            stdout.contains(&line),
            "policy reports {line:?}, got:\n{stdout}"
        );
    }
}

/// A missing `--config` override is a named error, never an empty
/// configuration — even against a drive that would otherwise open.
#[test]
fn a_missing_config_override_is_a_named_error() {
    let fixture = Fixture::new("missing-override");
    fixture.init();
    let missing = fixture.dir.join("elsewhere.toml");
    let mut argv = vec![
        "--config",
        missing.to_str().unwrap(),
        "sync",
        fixture.drive.to_str().unwrap(),
    ];
    argv.extend(fixture.cred_args());
    argv.push("status");
    let output = fixture.wyrd(&argv).output().expect("wyrd sync status runs");
    assert!(!output.status.success(), "a missing override must fail");
    let stderr = String::from_utf8(output.stderr).expect("stderr renders text");
    assert!(
        stderr.contains(missing.to_str().unwrap()),
        "the error names the missing file, got: {stderr:?}"
    );
}
