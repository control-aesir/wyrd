use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_daemon::LiveError;
#[test]
fn init_command_creates_a_reopenable_drive() {
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

    assert!(drive.join("DRIVE").is_file());
    assert!(drive.join("keystore").is_file());
    let identity = read_identity(&identity_file).unwrap();
    let engine = Engine::open_keystore(drive, "test-pass", identity).unwrap();
    assert!(engine.live_heads().unwrap().is_empty());
}

#[test]
fn hex_identity_files_are_supported() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    write_secret(&identity_file, format!("{}\r\n", hex::encode([0x11; 32])));
    let expected = DeviceIdentitySecret::from_bytes([0x11; 32])
        .unwrap()
        .device_id();
    assert_eq!(read_identity(&identity_file).unwrap().device_id(), expected);
}

#[test]
fn raw_identity_bytes_are_not_trimmed() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let mut identity = [0x11; 32];
    identity[31] = b'\n';
    write_secret(&identity_file, identity);
    assert!(read_identity(&identity_file).is_ok());
}

#[cfg(unix)]
#[test]
fn insecure_credential_permissions_are_rejected() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    write_secret(&identity_file, [0x11; 32]);
    fs::set_permissions(&identity_file, fs::Permissions::from_mode(0o644)).unwrap();
    let error = read_identity(&identity_file).unwrap_err();
    assert!(matches!(error, CliError::Credential { .. }));
}

#[cfg(unix)]
static UMASK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Process-umask guard for the init test below: umask is
/// process-global, so setters serialize on `UMASK_LOCK` and the mask
/// is restored on drop, even on panic. Unix-only.
#[cfg(unix)]
struct UmaskGuard {
    previous: u32,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn set_umask(mask: u32) -> UmaskGuard {
    let lock = UMASK_LOCK.lock().unwrap();
    // SAFETY: umask takes no pointers and only sets the calling
    // process's file-mode creation mask; UMASK_LOCK serializes every
    // setter in this binary, and Drop restores unconditionally.
    let previous = unsafe { libc::umask(mask as libc::mode_t) } as u32;
    UmaskGuard {
        previous,
        _lock: lock,
    }
}

#[cfg(unix)]
impl Drop for UmaskGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: restores the mask captured at construction; see `set_umask`.
        unsafe { libc::umask(self.previous as libc::mode_t) };
    }
}

/// `wyrd init` under a permissive umask produces owner-only custody
/// state: the user-visible end of the permission-hardening contract.
/// Unix-only.
#[cfg(unix)]
#[test]
fn init_under_a_permissive_umask_produces_owner_only_custody() {
    use std::os::unix::fs::PermissionsExt;
    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");

    let _guard = set_umask(0o000);
    command(vec![
        "init".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap();
    drop(_guard);

    assert_eq!(mode_of(&drive.join("store-key.wrap")) & 0o077, 0);
    assert_eq!(mode_of(&drive.join("keystore")) & 0o077, 0);
    assert_eq!(mode_of(&drive.join("LOCK")) & 0o077, 0);
    assert_eq!(mode_of(&drive) & 0o077, 0);
    assert_eq!(mode_of(&drive.join("DRIVE")) & 0o022, 0);
}

#[test]
fn missing_options_are_usage_errors() {
    let error = command(vec!["init".into(), "/tmp/drive".into()]).unwrap_err();
    assert!(matches!(error, CliError::Usage(_)));
}

#[test]
fn relay_flag_is_rejected_for_init() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    let error = command(vec![
        "init".into(),
        "/tmp/drive".into(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
        "--relay".into(),
        "ws://one.example".into(),
    ])
    .unwrap_err();
    assert!(
        matches!(error, CliError::Usage(message) if message.contains("unrecognized subcommand") || message.contains("unexpected"))
    );
}

/// A pacing deadline past a day stops being pacing, so mount refuses
/// it as a usage error before touching the drive.
#[test]
fn absurd_live_interval_is_a_usage_error() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    let error = command(vec![
        "mount".into(),
        "/tmp/drive".into(),
        "/tmp/mnt".into(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
        "--interval".into(),
        "86401".into(),
    ])
    .unwrap_err();
    assert!(matches!(error, CliError::Usage(message) if message.contains("--interval")));
}

/// A zero live idle pacing would busy-spin the loop, so mount
/// refuses it as a usage error before touching the drive.
#[test]
fn zero_live_interval_is_a_usage_error() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    let error = command(vec![
        "mount".into(),
        "/tmp/drive".into(),
        "/tmp/mnt".into(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
        "--interval".into(),
        "0".into(),
    ])
    .unwrap_err();
    assert!(matches!(error, CliError::Usage(message) if message.contains("--interval")));
}

#[test]
fn combine_status_fails_dead_sessions() {
    let clean = || TeardownStatus {
        loop_result: Ok(()),
        session_result: Ok(()),
        serving_result: Ok(()),
    };
    assert!(
        combine_status(clean()).is_ok(),
        "clean stop, clean server, and clean shutdowns exit zero"
    );
    assert!(
        matches!(
            combine_status(TeardownStatus {
                session_result: Err(CliError::Mount(std::io::Error::other("dead"))),
                ..clean()
            }),
            Err(CliError::Mount(_))
        ),
        "a dead serving thread fails the mount"
    );
    assert!(
        matches!(
            combine_status(TeardownStatus {
                loop_result: Err(CliError::Live(LiveError::Lock)),
                ..clean()
            }),
            Err(CliError::Live(_))
        ),
        "a loop failure dominates"
    );
    assert!(
        combine_status(TeardownStatus {
            loop_result: Err(CliError::Live(LiveError::Lock)),
            session_result: Err(CliError::Mount(std::io::Error::other("dead"))),
            serving_result: Err(CliError::Serving(std::io::Error::other("serving"))),
        })
        .is_err(),
        "everything failing still fails"
    );
}

/// Transport shutdown failures fail the mount instead of vanishing:
/// a serving shutdown that errored is an operational cause the exit
/// status must name. (Bulk is graceful-or-abort and infallible by
/// construction, so only serving can fail here.)
#[test]
fn combine_status_reports_transport_shutdown_failures() {
    let clean = || TeardownStatus {
        loop_result: Ok(()),
        session_result: Ok(()),
        serving_result: Ok(()),
    };
    assert!(
        matches!(
            combine_status(TeardownStatus {
                serving_result: Err(CliError::Serving(std::io::Error::other("serving down"))),
                ..clean()
            }),
            Err(CliError::Serving(_))
        ),
        "a serving shutdown error fails the mount as a serving error"
    );
    assert!(
        matches!(
            combine_status(TeardownStatus {
                loop_result: Err(CliError::Live(LiveError::Lock)),
                serving_result: Err(CliError::Serving(std::io::Error::other("serving down"))),
                ..clean()
            }),
            Err(CliError::Live(_))
        ),
        "the loop failure still dominates a serving failure"
    );
}

/// Credential files are opened `O_NOFOLLOW`: a symlink is refused
/// as a filesystem loop, never followed to its target.
#[cfg(unix)]
#[test]
fn credential_symlinks_are_rejected_without_following() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new();
    let target = temp.0.join("target");
    write_secret(&target, [0x11; 32]);
    let link = temp.0.join("link");
    symlink(&target, &link).unwrap();
    let error = read_identity(&link).unwrap_err();
    assert!(
        matches!(&error, CliError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ELOOP)),
        "a symlinked identity must fail closed: {error:?}"
    );

    // The passphrase rides the same reader: a symlinked
    // passphrase fails the wired credential path too.
    let identity_file = temp.0.join("identity");
    write_secret(&identity_file, [0x11; 32]);
    let passphrase_target = temp.0.join("passphrase-target");
    write_secret(&passphrase_target, b"test-pass\n");
    let passphrase_link = temp.0.join("passphrase");
    symlink(&passphrase_target, &passphrase_link).unwrap();
    let error = read_credentials(&Credentials {
        identity_file,
        passphrase_file: passphrase_link,
    })
    .unwrap_err();
    assert!(
        matches!(&error, CliError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ELOOP)),
        "a symlinked passphrase must fail closed: {error:?}"
    );
}

/// Credential files are bounded: over 4096 bytes is refused, and
/// exactly 4096 still reads.
#[cfg(unix)]
#[test]
fn oversized_credential_files_are_rejected() {
    let temp = TempDir::new();
    let big = temp.0.join("big");
    write_secret(&big, vec![b'x'; 4097]);
    let error = read_secret_file(&big).unwrap_err();
    assert!(
        matches!(
            &error,
            CliError::Credential {
                reason: "exceeds the 4096-byte size limit",
                ..
            }
        ),
        "oversize must name its stage: {error:?}"
    );

    let edge = temp.0.join("edge");
    write_secret(&edge, vec![b'x'; 4096]);
    assert!(
        read_secret_file(&edge).is_ok(),
        "exactly the limit still reads"
    );
}

/// Formatted CLI errors name paths and reasons, never secret
/// bytes: neither a rejected passphrase nor a rejected identity
/// scalar may appear in its own error text.
#[cfg(unix)]
#[test]
fn credential_contents_never_appear_in_errors() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    write_secret(&identity_file, [0x11; 32]);

    // A non-UTF8 passphrase fails after the secret is read: the
    // marker must not surface in the usage error.
    let passphrase_file = temp.0.join("passphrase");
    let mut marker = b"sekrit-marker-".to_vec();
    marker.extend_from_slice(&[0xff, 0xfe]);
    write_secret(&passphrase_file, &marker);
    let error = read_credentials(&Credentials {
        identity_file: identity_file.clone(),
        passphrase_file,
    })
    .unwrap_err();
    let text = format!("{error}");
    assert!(
        !text.contains("sekrit-marker"),
        "passphrase bytes leaked: {text}"
    );

    // A 32-byte scalar outside the curve range fails identity
    // validation: its hex must not surface either.
    let bad_scalar = temp.0.join("bad-scalar");
    write_secret(&bad_scalar, [0xff; 32]);
    let error = read_identity(&bad_scalar).unwrap_err();
    let text = format!("{error}");
    assert!(
        !text.contains(&hex::encode([0xff; 32])),
        "identity bytes leaked: {text}"
    );

    // The oversize stage names the file and the limit, never the
    // content that overflowed it.
    let big = temp.0.join("big");
    write_secret(&big, [b's'; 4097]);
    let error = read_secret_file(&big).unwrap_err();
    let text = format!("{error}");
    assert!(!text.contains("ssss"), "oversized content leaked: {text}");
}

/// Every `src/*.rs` file is reachable from a `mod` declaration: an
/// orphaned test module compiles nothing and fails nothing, so the
/// wiring itself needs a pin. Reads the source tree at the
/// build-time manifest directory; every file but `main.rs` must be
/// named by a `mod <stem>;` line in `main.rs`.
#[test]
fn every_src_file_is_a_declared_module() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let main = fs::read_to_string(src.join("main.rs")).unwrap();
    let mut orphaned = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&src).unwrap().collect();
    entries.sort_by_key(|entry| entry.as_ref().unwrap().file_name());
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let Some(stem) = name.strip_suffix(".rs") else {
            continue;
        };
        if stem == "main" {
            continue;
        }
        if !main.contains(&format!("mod {stem};")) {
            orphaned.push(name);
        }
    }
    assert!(orphaned.is_empty(), "uncompiled modules: {orphaned:?}");
}

/// Bare `wyrd vault <drive>` keeps starting the process (the 22b
/// surface); the subcommand selects the 22c query. Both shapes parse
/// through one optional subcommand, not two commands.
#[test]
fn vault_start_is_default_and_status_queries() {
    let creds = ["--identity-file", "/tmp/id", "--passphrase-file", "/tmp/pp"];
    let parse = |extra: &[&str]| {
        Cli::try_parse_from(
            ["wyrd", "vault", "/srv/drive"]
                .into_iter()
                .chain(creds)
                .chain(extra.iter().copied()),
        )
        .unwrap()
    };
    match parse(&[]).command {
        Command::Vault { action: None, .. } => {}
        other => panic!("bare vault must default to start, got: {other:?}"),
    }
    match parse(&["status"]).command {
        Command::Vault {
            action: Some(VaultAction::Status),
            ..
        } => {}
        other => panic!("vault status must parse, got: {other:?}"),
    }
    match parse(&["start"]).command {
        Command::Vault {
            action: Some(VaultAction::Start),
            ..
        } => {}
        other => panic!("vault start must parse, got: {other:?}"),
    }
}

/// `wyrd update` takes a drive, a local archive path, and the
/// credential paths to forward (U1=B): no download source, and the
/// parent never reads secrets — only the verification child opens
/// custody.
#[test]
fn update_parses_drive_archive_and_forwarded_credentials() {
    let temp = TempDir::new();
    let drive = temp.0.join("drive");
    let archive = temp.0.join("wyrd-0.3.0-alpha-linux-aarch64.tar.gz");

    let cli = Cli::try_parse_from([
        "wyrd",
        "update",
        drive.to_str().unwrap(),
        "--archive",
        archive.to_str().unwrap(),
        "--identity-file",
        "/tmp/id",
        "--passphrase-file",
        "/tmp/pp",
    ])
    .unwrap();
    let Command::Update {
        drive_dir,
        archive: parsed,
        restart,
        ..
    } = cli.command
    else {
        panic!("update must parse");
    };
    assert_eq!(drive_dir, drive);
    assert_eq!(parsed, archive);
    assert!(!restart);
}

/// A noncanonical archive name stops the update before anything is
/// disturbed, and the error names the expected shape.
#[test]
fn update_rejects_a_noncanonical_archive() {
    let temp = TempDir::new();
    let drive = temp.0.join("drive");
    fs::create_dir_all(&drive).unwrap();
    let archive = temp.0.join("abc123-wyrd-dist.tar.gz");
    fs::write(&archive, b"fake-archive").unwrap();

    let error = command(vec![
        "update".into(),
        drive.display().to_string(),
        "--archive".into(),
        archive.display().to_string(),
        "--identity-file".into(),
        "/tmp/id".into(),
        "--passphrase-file".into(),
        "/tmp/pp".into(),
    ])
    .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("wyrd-<version>-<os>-<arch>.tar.gz"),
        "{message}"
    );
}

/// Relay and restart flags belong together: relays without
/// `--restart` have no consumer, and `--restart` without a relay
/// cannot start the vault child.
#[test]
fn update_refuses_mismatched_restart_flags() {
    let temp = TempDir::new();
    let drive = temp.0.join("drive");
    fs::create_dir_all(&drive).unwrap();
    let base = || {
        vec![
            "update".into(),
            drive.display().to_string(),
            "--archive".into(),
            "wyrd-0.4.0-alpha-linux-aarch64.tar.gz".into(),
            "--identity-file".into(),
            "/tmp/id".into(),
            "--passphrase-file".into(),
            "/tmp/pp".into(),
        ]
    };
    let mut relayed = base();
    relayed.push("--relay".into());
    relayed.push("ws://localhost:9".into());
    let error = command(relayed).unwrap_err();
    assert!(error.to_string().contains("--restart-only"), "{error}");
    let mut restarted = base();
    restarted.push("--restart".into());
    let error = command(restarted).unwrap_err();
    assert!(
        error.to_string().contains("needs at least one --relay"),
        "{error}"
    );
}

/// `__update_verify` on a drive this build created verifies: open,
/// replay, heads, epochs, and byte-identical durable state — and a
/// second run proves idempotence (verification authors nothing, so
/// there is nothing to accumulate).
#[test]
fn update_verify_passes_a_compatible_drive_twice() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    let init = || {
        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap()
    };
    let verify = || {
        command(vec![
            "__update_verify".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap()
    };
    init();
    verify();
    verify();
}

/// `__update_verify` against a held drive refuses with no verdict:
/// contention is operator-fixable (stop it first), never an
/// incompatibility claim.
#[test]
fn update_verify_refuses_a_held_drive_without_a_verdict() {
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
    let _holder = Engine::open_keystore(drive.clone(), "test-pass", identity).unwrap();
    let error = command(vec![
        "__update_verify".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap_err();
    assert!(
        matches!(&error, CliError::Usage(message) if message.contains("stop it first")),
        "held drive must refuse without a verdict, got: {error}"
    );
}

/// `__update_verify` against a torn commit marker fails the
/// verification with the invariant named.
#[test]
fn update_verify_names_the_invariant_on_a_torn_store() {
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
    // Tear the commit marker: CURRENT must be sequence plus hash,
    // so garbage refuses at decode, not at open.
    fs::write(drive.join("CURRENT"), b"torn").unwrap();

    let error = command(vec![
        "__update_verify".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap_err();
    assert!(
        matches!(&error, CliError::Verification(message) if message.contains("invariant 2")),
        "torn store must fail with invariant 2, got: {error}"
    );
}
