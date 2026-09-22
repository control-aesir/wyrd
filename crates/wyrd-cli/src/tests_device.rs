use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_sync::runtime::EngineError;

/// Two drive directories on one host: an owner drive plus a newcomer
/// that pairs and joins it. One temp root with two subdirs, so the
/// pair can never collide with a sibling test's scratch space.
struct Pair {
    _temp: TempDir,
    owner_drive: PathBuf,
    owner_identity: PathBuf,
    owner_passphrase: PathBuf,
    newcomer_drive: PathBuf,
    newcomer_identity: PathBuf,
    newcomer_passphrase: PathBuf,
    pairing_file: PathBuf,
    invitation_file: PathBuf,
}

impl Pair {
    fn new() -> Self {
        let temp = TempDir::new();
        let owner_identity = temp.0.join("owner-identity");
        let owner_passphrase = temp.0.join("owner-passphrase");
        let newcomer_identity = temp.0.join("newcomer-identity");
        let newcomer_passphrase = temp.0.join("newcomer-passphrase");
        let owner_drive = temp.0.join("owner-drive");
        let newcomer_drive = temp.0.join("newcomer-drive");
        write_secret(&owner_identity, [0x22; 32]);
        write_secret(&owner_passphrase, b"owner-pass\n");
        write_secret(&newcomer_identity, [0x33; 32]);
        write_secret(&newcomer_passphrase, b"newcomer-pass\n");
        command(vec![
            "init".into(),
            owner_drive.display().to_string(),
            "--identity-file".into(),
            owner_identity.display().to_string(),
            "--passphrase-file".into(),
            owner_passphrase.display().to_string(),
        ])
        .unwrap();
        let pairing_file = temp.0.join("pairing");
        let invitation_file = temp.0.join("invitation");
        Pair {
            _temp: temp,
            owner_drive,
            owner_identity,
            owner_passphrase,
            newcomer_drive,
            newcomer_identity,
            newcomer_passphrase,
            pairing_file,
            invitation_file,
        }
    }

    fn owner_member(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "member".into(),
            self.owner_drive.display().to_string(),
            "--identity-file".into(),
            self.owner_identity.display().to_string(),
            "--passphrase-file".into(),
            self.owner_passphrase.display().to_string(),
        ];
        args.extend(action);
        args
    }

    fn newcomer_member(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "member".into(),
            self.newcomer_drive.display().to_string(),
            "--identity-file".into(),
            self.newcomer_identity.display().to_string(),
            "--passphrase-file".into(),
            self.newcomer_passphrase.display().to_string(),
        ];
        args.extend(action);
        args
    }

    fn newcomer_device(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "device".into(),
            self.newcomer_drive.display().to_string(),
            "--identity-file".into(),
            self.newcomer_identity.display().to_string(),
            "--passphrase-file".into(),
            self.newcomer_passphrase.display().to_string(),
        ];
        args.extend(action);
        args
    }

    fn owner_device(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "device".into(),
            self.owner_drive.display().to_string(),
            "--identity-file".into(),
            self.owner_identity.display().to_string(),
            "--passphrase-file".into(),
            self.owner_passphrase.display().to_string(),
        ];
        args.extend(action);
        args
    }

    /// The owner's canonical tip epoch, read straight from the
    /// keystore: proves whether an invite path committed anything.
    fn owner_tip_epoch(&self) -> u64 {
        Engine::open_keystore(
            self.owner_drive.clone(),
            "owner-pass",
            read_identity(&self.owner_identity).unwrap(),
        )
        .unwrap()
        .membership_log()
        .known_state()
        .expect("owner tip")
        .epoch
    }
    /// Stage pairing and return the public (device, encryption key)
    /// hex pair the owner invites with.
    fn stage_pairing(&self) -> (String, String) {
        command(self.newcomer_device(vec![
            "pairing-request".into(),
            self.pairing_file.display().to_string(),
        ]))
        .unwrap();
        let pairing = fs::read_to_string(&self.pairing_file).unwrap();
        let mut lines = pairing.lines();
        let device = lines
            .next()
            .and_then(|line| line.strip_prefix("device "))
            .expect("pairing names the device")
            .to_owned();
        let key = lines
            .next()
            .and_then(|line| line.strip_prefix("encryption-key "))
            .expect("pairing names the encryption key")
            .to_owned();
        (device, key)
    }

    /// The full pairing flow through the real command surface: stage
    /// pairing, admit plus invitation file, join. Returns the
    /// newcomer's (device, encryption key) for caller assertions.
    fn pair_and_join(&self) -> (DeviceId, wyrd_format::DeviceEncryptionKey) {
        let (device, key) = self.stage_pairing();
        command(self.owner_member(vec![
            "invite".into(),
            device.clone(),
            key.clone(),
            self.invitation_file.display().to_string(),
        ]))
        .unwrap();
        command(self.newcomer_device(vec![
            "join".into(),
            self.invitation_file.display().to_string(),
        ]))
        .unwrap();
        (
            parse_device_id(&device).unwrap(),
            parse_encryption_key(&key).unwrap(),
        )
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

#[test]
fn pairing_join_round_trip() {
    let pair = Pair::new();
    let owner = device_id_of(&[0x22; 32]);
    let (newcomer, _) = pair.pair_and_join();

    // The owner identifies itself with its registered key (minted
    // at creation, so the test asserts presence, not value).
    command(pair.owner_device(vec!["id".into()])).unwrap();
    let owner_report = device_id_report(
        &Engine::open_keystore(
            pair.owner_drive.clone(),
            "owner-pass",
            read_identity(&pair.owner_identity).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        owner_report.contains(&owner.to_string()),
        "owner identifies itself"
    );
    assert!(
        owner_report.contains("encryption-key ") && !owner_report.contains("unregistered"),
        "owner key is registered at genesis: {owner_report}"
    );

    // The newcomer reopens from member custody: device id resolves
    // and the log projects (genesis only — its own admission arrives
    // with catch-up, so the key reads unregistered). Scoped: the open
    // engine holds the store lock, and the list command below needs
    // the same directory.
    command(pair.newcomer_device(vec!["id".into()])).unwrap();
    let list = {
        let newcomer_engine = Engine::open_keystore(
            pair.newcomer_drive.clone(),
            "newcomer-pass",
            read_identity(&pair.newcomer_identity).unwrap(),
        )
        .unwrap();
        let report = device_id_report(&newcomer_engine).unwrap();
        assert!(
            report.contains(&newcomer.to_string()),
            "newcomer identifies itself"
        );
        assert!(
            report.contains("unregistered"),
            "fresh join holds genesis only: {report}"
        );
        member_list_report(&newcomer_engine).unwrap()
    };

    // Membership reads work over the member keystore.
    command(pair.newcomer_member(vec!["list".into()])).unwrap();
    assert!(
        list.contains(&owner.to_string()),
        "newcomer projects the genesis membership"
    );
    assert_eq!(newcomer, device_id_of(&[0x33; 32]));
}

#[test]
fn join_without_pairing_refuses() {
    let pair = Pair::new();
    // An invitation file must exist to reach the pairing check, so
    // pair first on a throwaway dir, then join a fresh dir without
    // staging.
    pair.pair_and_join();
    let fresh = pair._temp.0.join("fresh-drive");
    let error = command(vec![
        "device".into(),
        fresh.display().to_string(),
        "--identity-file".into(),
        pair.newcomer_identity.display().to_string(),
        "--passphrase-file".into(),
        pair.newcomer_passphrase.display().to_string(),
        "join".into(),
        pair.invitation_file.display().to_string(),
    ])
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::MissingPairingSecret)),
        "join without pairing names the missing stage: {error:?}"
    );
}

#[test]
fn tampered_invitation_fails_closed() {
    let pair = Pair::new();
    pair.pair_and_join();
    // Truncation never decodes.
    let truncated = pair._temp.0.join("truncated-invitation");
    let bytes = fs::read(&pair.invitation_file).unwrap();
    fs::write(&truncated, &bytes[..10]).unwrap();
    assert!(
        command(pair.newcomer_device(vec!["join".into(), truncated.display().to_string(),]))
            .is_err(),
        "truncated invitation refuses"
    );
    // A flipped ciphertext byte decodes but never opens.
    let flipped = pair._temp.0.join("flipped-invitation");
    let mut forged = bytes.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    fs::write(&flipped, &forged).unwrap();
    assert!(
        command(pair.newcomer_device(vec!["join".into(), flipped.display().to_string(),])).is_err(),
        "forged invitation refuses"
    );
}

#[test]
fn non_owner_invite_refuses() {
    let pair = Pair::new();
    pair.pair_and_join();
    // The newcomer holds genesis only: it is no owner anywhere, so
    // its invite authors nothing.
    let third = device_id_of(&[0x44; 32]);
    let third_key = encryption_key_of(&[0x44; 32]);
    let out = pair._temp.0.join("third-invitation");
    let error = command(pair.newcomer_member(vec![
        "invite".into(),
        third.to_string(),
        third_key.to_string(),
        out.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotOwner)),
        "member invite is owner-enforced by the engine: {error:?}"
    );
    assert!(!out.exists(), "a refused invite writes no file");
}

#[test]
fn non_owner_reissue_refuses() {
    let pair = Pair::new();
    pair.pair_and_join();
    // The newcomer holds genesis only: it is no owner anywhere, so
    // its reissue authors nothing — the engine owns the policy.
    let third = device_id_of(&[0x44; 32]);
    let out = pair._temp.0.join("newcomer-reissue");
    let error = command(pair.newcomer_member(vec![
        "reissue-invitation".into(),
        third.to_string(),
        out.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotOwner)),
        "member reissue is owner-enforced by the engine: {error:?}"
    );
    assert!(!out.exists(), "a refused reissue writes no file");
}

#[test]
fn double_invite_refuses() {
    let pair = Pair::new();
    let (newcomer, newcomer_key) = pair.pair_and_join();
    let out = pair._temp.0.join("second-invitation");
    let error = command(pair.owner_member(vec![
        "invite".into(),
        newcomer.to_string(),
        newcomer_key.to_string(),
        out.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::AlreadyMember)),
        "second invite names the existing membership: {error:?}"
    );
}

#[test]
fn invite_to_existing_destination_refuses_before_committing() {
    let pair = Pair::new();
    let (device, key) = pair.stage_pairing();
    fs::write(&pair.invitation_file, b"occupied").unwrap();
    let error = command(pair.owner_member(vec![
        "invite".into(),
        device,
        key,
        pair.invitation_file.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Usage(_)),
        "existing destination is refused, not overwritten: {error:?}"
    );
    assert_eq!(
        pair.owner_tip_epoch(),
        1,
        "no transition commits when the destination is refused"
    );
}

#[test]
fn invite_to_missing_parent_refuses_before_committing() {
    let pair = Pair::new();
    let (device, key) = pair.stage_pairing();
    let out = pair._temp.0.join("no-such-dir").join("invitation");
    let error = command(pair.owner_member(vec![
        "invite".into(),
        device,
        key,
        out.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Usage(_)),
        "uncreatable destination fails before any commit: {error:?}"
    );
    assert!(!out.exists(), "no claim file left behind");
    assert_eq!(
        pair.owner_tip_epoch(),
        1,
        "no transition commits when the destination is uncreatable"
    );
}

#[test]
fn reissue_recovers_lost_invitation_through_the_surface() {
    let pair = Pair::new();
    let (device, key) = pair.stage_pairing();
    // Invite, then lose the file: the admission stands with no
    // published invitation, like a death between commit and write.
    command(pair.owner_member(vec![
        "invite".into(),
        device.clone(),
        key,
        pair.invitation_file.display().to_string(),
    ]))
    .unwrap();
    fs::remove_file(&pair.invitation_file).unwrap();
    // Reissue to a fresh path and join from it: recovery without
    // re-admission.
    let reissued = pair._temp.0.join("reissued-invitation");
    command(pair.owner_member(vec![
        "reissue-invitation".into(),
        device,
        reissued.display().to_string(),
    ]))
    .unwrap();
    command(pair.newcomer_device(vec!["join".into(), reissued.display().to_string()])).unwrap();
    // Membership reads work over the recovered join.
    command(pair.newcomer_member(vec!["list".into()])).unwrap();
    // Nothing to reissue for a stranger, and no silent overwrite of
    // an existing destination.
    let stranger = device_id_of(&[0x44; 32]);
    let error = command(pair.owner_member(vec![
        "reissue-invitation".into(),
        stranger.to_string(),
        reissued.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Usage(_)),
        "existing destination refuses before any lookup: {error:?}"
    );
    let elsewhere = pair._temp.0.join("elsewhere-invitation");
    let error = command(pair.owner_member(vec![
        "reissue-invitation".into(),
        stranger.to_string(),
        elsewhere.display().to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotMember)),
        "unknown device has no invitation: {error:?}"
    );
}
