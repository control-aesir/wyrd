use super::tests_harness::{write_secret, TempDir};
use super::*;

/// Export round-trips an authored drive to a plain tree through the
/// real command surface: init, author through the node, export, and
/// read the output back with plain filesystem calls — no wyrd types
/// touch the assertions after the export returns.
#[test]
fn export_command_materializes_a_plain_tree() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    let out = temp.0.join("out");
    write_secret(&identity_file, [0x22; 32]);
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
    let store = FsObjectStore::open(drive.clone()).unwrap();
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, store).unwrap();
    daemon.put_file("hello.txt", b"hello export").unwrap();
    daemon.put_file("sub/nested.txt", b"nested").unwrap();
    daemon.put_file("sub/gone.txt", b"gone").unwrap();
    // Removing the last file keeps the emptied directory, matching
    // the mutation layer — export must carry it across.
    daemon.remove("sub/gone.txt").unwrap();
    drop(daemon);

    command(vec![
        "export".into(),
        drive.display().to_string(),
        out.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap();

    assert_eq!(fs::read(out.join("hello.txt")).unwrap(), b"hello export");
    assert_eq!(
        fs::read(out.join("sub").join("nested.txt")).unwrap(),
        b"nested"
    );
    assert!(
        out.join("sub").is_dir() && fs::read_dir(out.join("sub")).unwrap().count() == 1,
        "the emptied directory survives with only its remaining child"
    );
}

/// Export refuses a populated destination instead of merging into it.
#[test]
fn export_command_refuses_a_populated_destination() {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    let out = temp.0.join("out");
    write_secret(&identity_file, [0x22; 32]);
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
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("mine.txt"), b"not yours").unwrap();

    let error = command(vec![
        "export".into(),
        drive.display().to_string(),
        out.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap_err();

    assert!(
        matches!(error, CliError::Export(_)),
        "unexpected: {error:?}"
    );
    assert_eq!(fs::read(out.join("mine.txt")).unwrap(), b"not yours");
}
