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
    assert_eq!(
        read_identity(&identity_file).unwrap().as_bytes(),
        &[0x11; 32]
    );
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

#[test]
fn combine_status_fails_dead_sessions() {
    let clean = || TeardownStatus {
        loop_result: Ok(()),
        session_result: Ok(()),
        bulk_result: Ok(()),
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
            bulk_result: Err(CliError::Bulk(std::io::Error::other("bulk"))),
            serving_result: Err(CliError::Serving(std::io::Error::other("serving"))),
        })
        .is_err(),
        "everything failing still fails"
    );
}

/// Transport shutdown failures fail the mount instead of vanishing:
/// a bulk close that timed out and a serving shutdown that errored
/// are both operational causes the exit status must name, under
/// their own variants.
#[test]
fn combine_status_reports_transport_shutdown_failures() {
    let clean = || TeardownStatus {
        loop_result: Ok(()),
        session_result: Ok(()),
        bulk_result: Ok(()),
        serving_result: Ok(()),
    };
    assert!(
        matches!(
            combine_status(TeardownStatus {
                bulk_result: Err(CliError::Bulk(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "bulk endpoint close timed out"
                ))),
                ..clean()
            }),
            Err(CliError::Bulk(_))
        ),
        "a timed-out bulk close fails the mount as a bulk error"
    );
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
