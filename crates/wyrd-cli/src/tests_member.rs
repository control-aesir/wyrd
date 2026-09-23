use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_format::{ContentId, Entry, FsObjectStore, ObjectKind, ObjectStore, SnapshotId, Tree};
use wyrd_sync::runtime::EngineError;

struct Fixture {
    _temp: TempDir,
    drive: PathBuf,
    identity_file: PathBuf,
    passphrase_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
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
        Fixture {
            _temp: temp,
            drive,
            identity_file,
            passphrase_file,
        }
    }

    fn args(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "member".into(),
            self.drive.display().to_string(),
            "--identity-file".into(),
            self.identity_file.display().to_string(),
            "--passphrase-file".into(),
            self.passphrase_file.display().to_string(),
        ];
        args.extend(action);
        args
    }

    fn open(&self) -> Engine {
        let identity = read_identity(&self.identity_file).unwrap();
        Engine::open_keystore(self.drive.clone(), "test-pass", identity).unwrap()
    }
}

/// The x-only pubkey a 32-byte secret names.
fn device_id_of(secret: &[u8; 32]) -> DeviceId {
    let keys = nostr::key::Keys::new(nostr::key::SecretKey::from_slice(secret).unwrap());
    DeviceId::from_bytes(*keys.public_key().as_bytes())
}

/// The encryption key a 32-byte secret names.
fn encryption_key_of(secret: &[u8; 32]) -> wyrd_format::DeviceEncryptionKey {
    let keys = nostr::key::Keys::new(nostr::key::SecretKey::from_slice(secret).unwrap());
    wyrd_format::DeviceEncryptionKey::from_bytes(*keys.public_key().as_bytes())
}

/// Admit a device through the CLI invite command: the member
/// commands under test administer existing membership, and admission
/// setup exercises the same invite surface a user drives.
fn admit(fixture: &Fixture, secret: &[u8; 32]) -> DeviceId {
    let id = device_id_of(secret);
    let key = encryption_key_of(secret);
    let out = fixture._temp.0.join(format!("invitation-{id}"));
    command(fixture.args(vec![
        "invite".into(),
        id.to_string(),
        key.to_string(),
        out.display().to_string(),
    ]))
    .unwrap();
    assert!(out.exists(), "invite writes the sealed invitation");
    id
}

/// Reads project a fresh drive: epoch 1, the owner alone, canonical
/// genesis, no frozen conflict, and the epoch-1 secret held.
#[test]
fn member_reports_describe_a_fresh_drive() {
    let fixture = Fixture::new();
    command(fixture.args(vec!["list".into()])).unwrap();
    command(fixture.args(vec!["log".into()])).unwrap();
    command(fixture.args(vec!["status".into()])).unwrap();

    let engine = fixture.open();
    let owner = device_id_of(&[0x22; 32]);
    let list = member_list_report(&engine).unwrap();
    assert!(list.contains("epoch 1"), "list names the epoch");
    assert!(
        list.contains(&format!("owner {owner}")),
        "list names the owner"
    );
    let log = member_log_report(&engine).unwrap();
    assert!(log.contains("epoch 1"), "log shows genesis");
    assert!(log.contains("canonical"), "genesis is canonical");
    let status = member_status_report(&engine).unwrap();
    assert!(status.contains("members 1 owners 1"), "one owner-member");
    assert!(status.contains("frozen: no"), "nothing frozen");
    assert!(status.contains("held secrets: 1"), "epoch-1 secret held");
}

/// Remove administrates membership: the device leaves at a new epoch
/// and vanishes from the list.
#[test]
fn member_remove_administers_membership() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    command(fixture.args(vec!["remove".into(), second.to_string()])).unwrap();

    let engine = fixture.open();
    let tip = engine.membership_log().known_state().expect("tip");
    assert_eq!(tip.epoch, 3, "admit plus removal");
    assert!(
        !engine
            .membership_log()
            .members_of(&tip.transition_id)
            .expect("members")
            .contains(&second),
        "removed device leaves"
    );
    assert!(
        !member_list_report(&engine)
            .unwrap()
            .contains(&second.to_string()),
        "list no longer names the removed device"
    );
}

/// Removing a stranger fails closed with the engine's reason.
#[test]
fn member_remove_unknown_is_refused() {
    let fixture = Fixture::new();
    let stranger = device_id_of(&[0x55; 32]);
    let error = command(fixture.args(vec!["remove".into(), stranger.to_string()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotMember)),
        "unexpected: {error:?}"
    );
}

/// A stranger's credentials fail at open: the keystore binds to its
/// owner's device identity, and joined devices carry their own
/// keystore (invite/join is a separate tracked issue). The engine's
/// owner-only authority stays covered by the sync tests and the
/// handover test below.
#[test]
fn member_open_by_non_owner_is_refused() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    let stranger_file = fixture._temp.0.join("stranger");
    write_secret(&stranger_file, [0x55; 32]);
    let error = command(vec![
        "member".into(),
        fixture.drive.display().to_string(),
        "--identity-file".into(),
        stranger_file.display().to_string(),
        "--passphrase-file".into(),
        fixture.passphrase_file.display().to_string(),
        "remove".into(),
        second.to_string(),
    ])
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::OwnerMismatch)),
        "unexpected: {error:?}"
    );
}

/// Last-owner removal is valid but terminal: without `--yes` the CLI
/// refuses to author it; with confirmation the owner set empties.
#[test]
fn member_remove_sole_owner_needs_confirmation() {
    let fixture = Fixture::new();
    let owner = device_id_of(&[0x22; 32]);
    let error = command(fixture.args(vec!["remove".into(), owner.to_string()])).unwrap_err();
    assert!(matches!(error, CliError::Usage(_)), "unexpected: {error:?}");

    command(fixture.args(vec!["remove".into(), owner.to_string(), "--yes".into()])).unwrap();
    let engine = fixture.open();
    let tip = engine.membership_log().known_state().expect("tip");
    assert!(
        engine
            .membership_log()
            .owners_of(&tip.transition_id)
            .expect("owners")
            .is_empty(),
        "owner set empties with the sole owner"
    );
}
/// Rotate bumps the epoch with membership untouched.
#[test]
fn member_rotate_bumps_epoch_keeps_membership() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    command(fixture.args(vec!["rotate".into()])).unwrap();

    let engine = fixture.open();
    let tip = engine.membership_log().known_state().expect("tip");
    assert_eq!(tip.epoch, 3, "admit plus rotation");
    let members = engine
        .membership_log()
        .members_of(&tip.transition_id)
        .expect("members");
    assert!(members.contains(&second), "rotation removes nobody");
    assert_eq!(members.len(), 2, "owner plus second");
}

/// Set-owner hands authority over: the old owner loses it on the
/// spot.
#[test]
fn member_set_owner_hands_authority_over() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    command(fixture.args(vec!["set-owner".into(), second.to_string()])).unwrap();

    {
        let engine = fixture.open();
        let tip = engine.membership_log().known_state().expect("tip");
        assert_eq!(tip.epoch, 3, "admit plus handover");
        let owners = engine
            .membership_log()
            .owners_of(&tip.transition_id)
            .expect("owners");
        assert_eq!(
            owners.iter().collect::<Vec<_>>(),
            [&second],
            "ownership moves"
        );
    }

    let third = device_id_of(&[0x66; 32]);
    let error = command(fixture.args(vec!["remove".into(), third.to_string()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotOwner)),
        "old owner lost authority: {error:?}"
    );
}

/// Rotate carries the namespace: a drive with files serves them at
/// the new epoch afterwards, and the carry extends the old tip.
#[test]
fn member_rotate_carries_files_forward() {
    let fixture = Fixture::new();
    let (tree, first) = write_file(&fixture, "kept.txt", b"kept");
    command(fixture.args(vec!["rotate".into()])).unwrap();

    let engine = fixture.open();
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the carry serves the files after rotate");
    assert_eq!(heads[0].snapshot().epoch, 2);
    assert_eq!(heads[0].snapshot().tree, tree);
    assert_eq!(
        heads[0].snapshot().parents,
        vec![first],
        "the carry extends the old tip"
    );
}

/// Author one file snapshot over the fixture drive, returning its
/// tree and snapshot id.
fn write_file(fixture: &Fixture, name: &str, bytes: &[u8]) -> (ContentId, SnapshotId) {
    let identity = read_identity(&fixture.identity_file).unwrap();
    let mut engine = Engine::open_keystore(fixture.drive.clone(), "test-pass", identity).unwrap();
    let mut store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let chunk = store.insert(ObjectKind::Chunk, bytes).unwrap();
    let entry = Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap();
    let tree = Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    let first = engine.author_snapshot(&store, tree).unwrap();
    (tree, first.snapshot().snapshot_id())
}

/// Invite carries the namespace: the newcomer's epoch starts from
/// the carried files, not an empty view.
#[test]
fn member_invite_carries_files_forward() {
    let fixture = Fixture::new();
    let (tree, first) = write_file(&fixture, "kept.txt", b"kept");
    admit(&fixture, &[0x44; 32]);

    let engine = fixture.open();
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the carry serves the files after invite");
    assert_eq!(heads[0].snapshot().epoch, 2);
    assert_eq!(heads[0].snapshot().tree, tree);
    assert_eq!(heads[0].snapshot().parents, vec![first]);
}

/// Remove carries the namespace for the remaining owner.
#[test]
fn member_remove_carries_files_forward() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    let (tree, first) = write_file(&fixture, "kept.txt", b"kept");
    command(fixture.args(vec!["remove".into(), second.to_string()])).unwrap();

    let engine = fixture.open();
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the carry serves the files after remove");
    assert_eq!(heads[0].snapshot().epoch, 3, "admit plus removal");
    assert_eq!(heads[0].snapshot().tree, tree);
    assert_eq!(heads[0].snapshot().parents, vec![first]);
}

/// Handover carries the namespace: the outgoing owner stays a
/// member, so its transition still carries.
#[test]
fn member_set_owner_carries_files_forward() {
    let fixture = Fixture::new();
    let second = admit(&fixture, &[0x44; 32]);
    let (tree, first) = write_file(&fixture, "kept.txt", b"kept");
    command(fixture.args(vec!["set-owner".into(), second.to_string()])).unwrap();

    let engine = fixture.open();
    let heads = engine.live_heads().unwrap();
    assert_eq!(heads.len(), 1, "the carry serves the files after handover");
    assert_eq!(heads[0].snapshot().epoch, 3, "admit plus handover");
    assert_eq!(heads[0].snapshot().tree, tree);
    assert_eq!(heads[0].snapshot().parents, vec![first]);
}
