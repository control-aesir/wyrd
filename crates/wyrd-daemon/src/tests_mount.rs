use super::logging::build_mount_subscriber;
use super::tests_harness::{reclaim, write_secret, TempDir, WithoutRustLog, JOIN_TIMEOUT};
use super::*;

/// Mount diagnostics initialize a per-mount log file. A second init
/// in the same process truncates its own path but reuses the
/// installed subscriber — the first install wins by design — and
/// records that reuse instead of claiming a fresh install. (This
/// test is the only global installer in the binary, so its first
/// init is the installing one.)
#[test]
fn mount_diagnostics_create_a_per_mount_log() {
    let temp = TempDir::new();
    let drive = temp.0.join("drive");
    fs::create_dir_all(&drive).unwrap();

    let first = init_mount_diagnostics(&drive, false).unwrap();
    assert_eq!(first, drive.join("mount.log"));
    assert!(first.is_file(), "the mount leaves a log in the drive dir");

    fs::write(&first, b"stale").unwrap();
    let second = init_mount_diagnostics(&drive, true).unwrap();
    assert_eq!(second, first);
    let text = fs::read_to_string(&second).unwrap();
    assert!(
        !text.contains("stale"),
        "each mount starts its own truncated log"
    );
    assert!(
        text.contains("reusing the installed subscriber"),
        "the reuse is recorded, not silent: {text}"
    );
}

/// End-to-end diagnostics: events emitted under a thread-scoped
/// subscriber land in that subscriber's file, and `--verbose`
/// controls the debug gate — without touching the process-global
/// subscriber other tests may have installed.
#[test]
fn mount_events_reach_the_configured_log_file() {
    // RUST_LOG would override the gate under test; nothing else in
    // this binary reads it, so take it out of the way under a guard.
    let _no_rust_log = WithoutRustLog::take();

    let temp = TempDir::new();
    let log = temp.0.join("mount.log");
    let subscriber = build_mount_subscriber(fs::File::create(&log).unwrap(), false);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(stage = "test", "visible at info");
        tracing::debug!(opcode = "lookup", latency_us = 7, "hidden without verbose");
    });
    let text = fs::read_to_string(&log).unwrap();
    assert!(
        text.contains("visible at info"),
        "info events reach the file: {text}"
    );
    assert!(
        !text.contains("hidden without verbose"),
        "debug stays gated without verbose: {text}"
    );

    let verbose_log = temp.0.join("verbose.log");
    let subscriber = build_mount_subscriber(fs::File::create(&verbose_log).unwrap(), true);
    tracing::subscriber::with_default(subscriber, || {
        tracing::debug!(opcode = "lookup", latency_us = 7, "visible with verbose");
    });
    let text = fs::read_to_string(&verbose_log).unwrap();
    assert!(
        text.contains("visible with verbose"),
        "verbose opens the debug gate: {text}"
    );
}

/// The shutdown noise gate: iroh's relay-transport teardown event
/// is suppressed once the shutdown latch is tripped (clean SIGINT
/// path goes quiet) and stays loud otherwise (a mid-operation
/// relay death must still fail visibly). The latch is
/// process-global, so save and restore it around the emissions.
#[test]
fn relay_teardown_noise_gated_on_shutdown_latch() {
    let _no_rust_log = WithoutRustLog::take();
    let was = SHUTDOWN.load(Ordering::Relaxed);

    // The exact event iroh `=1.1.0` emits from
    // `iroh::socket::transports::relay` on endpoint close.
    let emit_noise = || {
        tracing::error!(target: "iroh::socket::transports::relay", "relay_recv_channel closed");
    };

    let temp = TempDir::new();
    SHUTDOWN.store(true, Ordering::Relaxed);
    let quiet_log = temp.0.join("quiet.log");
    let subscriber = build_mount_subscriber(fs::File::create(&quiet_log).unwrap(), false);
    tracing::subscriber::with_default(subscriber, emit_noise);

    SHUTDOWN.store(false, Ordering::Relaxed);
    let loud_log = temp.0.join("loud.log");
    let subscriber = build_mount_subscriber(fs::File::create(&loud_log).unwrap(), false);
    tracing::subscriber::with_default(subscriber, emit_noise);

    SHUTDOWN.store(was, Ordering::Relaxed);
    let quiet = fs::read_to_string(&quiet_log).unwrap();
    assert!(
        !quiet.contains("relay_recv_channel closed"),
        "teardown noise stays out of the log once shutdown is underway: {quiet}"
    );
    let loud = fs::read_to_string(&loud_log).unwrap();
    assert!(
        loud.contains("relay_recv_channel closed"),
        "the same event still fails visibly outside shutdown: {loud}"
    );
}

/// Two subscribers route to their own files: per-mount file routing
/// holds wherever a subscriber is constructed per mount, while the
/// process-global install stays first-wins by design (see
/// [`init_mount_diagnostics`]).
#[test]
fn mount_subscribers_route_to_their_own_files() {
    let temp = TempDir::new();
    let first = temp.0.join("first.log");
    let second = temp.0.join("second.log");
    let first_subscriber = build_mount_subscriber(fs::File::create(&first).unwrap(), false);
    let second_subscriber = build_mount_subscriber(fs::File::create(&second).unwrap(), false);
    tracing::subscriber::with_default(first_subscriber, || {
        tracing::info!("event for the first log");
    });
    tracing::subscriber::with_default(second_subscriber, || {
        tracing::info!("event for the second log");
    });
    let first_text = fs::read_to_string(&first).unwrap();
    let second_text = fs::read_to_string(&second).unwrap();
    assert!(
        first_text.contains("event for the first log")
            && !first_text.contains("event for the second log"),
        "the first subscriber keeps its own record: {first_text}"
    );
    assert!(
        second_text.contains("event for the second log")
            && !second_text.contains("event for the first log"),
        "the second subscriber keeps its own record: {second_text}"
    );
}

/// `--verbose` is a mount-only diagnostics flag: it parses on
/// mount and stays rejected for init like the other mount flags.
#[test]
fn mount_accepts_a_verbose_diagnostics_flag() {
    let cli = Cli::try_parse_from([
        "wyrd".to_owned(),
        "mount".into(),
        "/tmp/drive".into(),
        "/tmp/mnt".into(),
        "--identity-file".into(),
        "/tmp/id".into(),
        "--passphrase-file".into(),
        "/tmp/pp".into(),
        "--verbose".into(),
    ])
    .unwrap();
    assert!(
        matches!(cli.command, Command::Mount { verbose: true, .. }),
        "mount carries the verbose diagnostics flag"
    );
}

/// The mount serves a read-write `wyrd` filesystem: the backend
/// carries the live daemon's mutation channel, so the kernel must
/// not gate writes behind a read-only flag.
#[test]
fn mount_uses_a_read_write_filesystem_name() {
    let config = session_config();
    assert!(
        config
            .mount_options
            .iter()
            .all(|option| !matches!(option, MountOption::RO)),
        "the mount is read-write"
    );
    assert!(
        config
            .mount_options
            .iter()
            .any(|option| matches!(option, MountOption::FSName(name) if name == "wyrd")),
        "the mount names itself"
    );
}

/// The mount preamble composes without a kernel: open the
/// keystore, build the daemon over the file store, author, and
/// the classified projection serves. That is the composition this
/// covers; the serving endpoint, bulk source, mailbox, signal
/// handler, and FUSE session creation remain live-mount-only
/// (see the gated test below).
#[test]
fn mount_preamble_projects_authorized_heads_without_fuse() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    command(vec![
        "init".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap();

    let identity = read_identity(&identity_file).unwrap();
    let engine = Engine::open_keystore(drive.clone(), "test-pass", identity).unwrap();
    let store = FsObjectStore::open(drive).unwrap();
    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.put_file("hello.txt", b"hello mount").unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("hello.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 11).unwrap(), b"hello mount");
}

/// The full live mount: init, author, mount in a thread, read
/// through the mountpoint, write a file through it and read it
/// back, shut down, rejoin cleanly, and prove the write survived
/// by reopening the drive. Ignored by default — opting in is the
/// test runner's job, so an explicit run always attempts the mount
/// instead of silently passing. Needs kernel FUSE plus local
/// networking for the serving endpoint. Run it where both hold:
/// `cargo nextest run -p wyrd-daemon --bin wyrd --run-ignored all`
#[test]
#[ignore = "needs kernel FUSE and local networking"]
fn live_mount_serves_read_write_until_shutdown() {
    // The shutdown latch is process-global: start unset so a
    // previous run in this process cannot cut this mount short.
    SHUTDOWN.store(false, Ordering::Relaxed);
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    command(vec![
        "init".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap();

    let identity = read_identity(&identity_file).unwrap();
    let engine = Engine::open_keystore(drive.clone(), "test-pass", identity.clone()).unwrap();
    let store = FsObjectStore::open(drive.clone()).unwrap();
    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.put_file("hello.txt", b"hello mount").unwrap();
    drop(daemon);

    let mountpoint = temp.0.join("mnt");
    fs::create_dir_all(&mountpoint).unwrap();
    // The guard owns the mount thread: an assertion panic
    // anywhere below still signals shutdown and rejoins instead
    // of orphaning the mount. The explicit join reports the
    // mount outcome; the Drop path stays best-effort (it must
    // never panic while unwinding).
    let drive_path = drive.clone();
    let mut mount = MountGuard {
        server: Some(std::thread::spawn(move || {
            mount(drive, mountpoint, Vec::new(), false, "test-pass", identity)
        })),
    };
    let target = temp.0.join("mnt").join("hello.txt");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !target.is_file() && std::time::Instant::now() <= deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !target.is_file() {
        mount.shutdown_and_join("during startup");
        panic!("the mount did not serve in time");
    }
    assert_eq!(fs::read(&target).unwrap(), b"hello mount");
    // The mount serves read-write: a file written through the
    // mountpoint reads back, and survives the mount: reopening
    // the drive finds the authored content.
    let written = temp.0.join("mnt").join("written.txt");
    fs::write(&written, b"hello write").unwrap();
    assert_eq!(fs::read(&written).unwrap(), b"hello write");
    mount.shutdown_and_join("during shutdown");
    assert!(
        fs::read_dir(temp.0.join("mnt")).unwrap().next().is_none(),
        "a clean unmount releases the mountpoint"
    );
    let identity = read_identity(&identity_file).unwrap();
    let engine = Engine::open_keystore(drive_path.clone(), "test-pass", identity).unwrap();
    let store = FsObjectStore::open(drive_path).unwrap();
    let mut daemon = Daemon::new(engine, store).unwrap();
    daemon.refresh_live_heads().unwrap();
    let node = daemon.view().lookup("written.txt").unwrap();
    let file = daemon.view().open(&node).unwrap();
    assert_eq!(daemon.view().read(&file, 0, 11).unwrap(), b"hello write");
}

/// Owns a spawned mount thread: signals shutdown and rejoins on
/// every exit path, so a failed assertion cannot orphan the
/// mount. Rejoins are bounded: a wedged FUSE thread fails the
/// test instead of hanging it. The tradeoff is explicit: on
/// expiry the handle detaches, so the thread and possibly the
/// mount may outlive the test's tempdir (already-open handles
/// keep working against removed paths; nothing new is served).
/// The explicit join reports mount errors; dropping stays
/// best-effort and never panics.
struct MountGuard {
    server: Option<std::thread::JoinHandle<Result<(), CliError>>>,
}

impl MountGuard {
    fn shutdown_and_join(&mut self, context: &str) {
        SHUTDOWN.store(true, Ordering::Relaxed);
        match self.server.take() {
                None => {}
                Some(server) => match reclaim(server, JOIN_TIMEOUT) {
                    Some(Err(_)) => panic!("the mount thread panicked {context}"),
                    Some(Ok(Err(error))) => panic!("the mount failed {context}: {error}"),
                    Some(Ok(Ok(()))) => {}
                    None => panic!("the mount thread did not exit within {JOIN_TIMEOUT:?} of shutdown {context}: FUSE may be wedged"),
                },
            }
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        if let Some(server) = self.server.take() {
            SHUTDOWN.store(true, Ordering::Relaxed);
            // Best-effort and bounded: never panic or hang while
            // unwinding; the explicit join reports errors.
            let _ = reclaim(server, JOIN_TIMEOUT);
        }
    }
}
