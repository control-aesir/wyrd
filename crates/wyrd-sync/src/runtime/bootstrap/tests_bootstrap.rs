use super::*;
use crate::control::bootstrap::seal_bootstrap;
use crate::control::{seal, KeyRotation, Message};
use crate::keys::capability::Capability;
use crate::runtime::test_util::TestDir;
use crate::transport::mailbox::{seal_for_recipient, MemoryMailbox, MemoryRelay};
use wyrd_format::TransitionId;

#[test]
fn an_interrupted_bootstrap_resumes_on_open() {
    let dir = TestDir::new("bootstrap-resume");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    let root = DriveRootKey::generate().unwrap();
    let epoch = EpochSecret::generate().unwrap();
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes).unwrap();
    let drive = DriveId::from_bytes(bytes);

    // Simulate the crash window: the custody record is durable but the
    // genesis transition was never committed.
    let custody = encode_custody(
        &identity.device_id(),
        &wrap_root(root.as_bytes(), "test-pass").unwrap(),
        &wrap_device_secret(encryption.as_bytes(), "test-pass").unwrap(),
        &escrow::wrap(&root.escrow_key(&drive, 1), &drive, 1, &epoch).unwrap(),
    );
    {
        let _store = DurableStore::open(dir.path.clone(), drive, "test-pass").unwrap();
        atomic_write(&dir.path, KEYSTORE_FILE, &custody).unwrap();
    }

    // Opening resumes and completes the deterministic genesis.
    let engine = open_keystore(dir.path.clone(), "test-pass", identity).unwrap();
    assert!(
        engine.log.known_state().is_some(),
        "the interrupted bootstrap is completed on open"
    );
    assert!(engine.live_heads().unwrap().is_empty());
}

#[test]
fn opening_with_a_different_identity_is_refused() {
    let dir = TestDir::new("bootstrap-owner");
    let identity = DeviceIdentitySecret::generate().unwrap();
    drop(create(dir.path.clone(), "test-pass", identity).unwrap());
    let other = DeviceIdentitySecret::generate().unwrap();
    assert!(matches!(
        open_keystore(dir.path.clone(), "test-pass", other),
        Err(EngineError::OwnerMismatch)
    ));
}

#[test]
fn member_custody_reopens_without_root_or_escrow() {
    let dir = TestDir::new("member-custody");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    // A member store holds the wrapped device secret and nothing
    // else: no root, no escrow. The store open writes DRIVE; the
    // custody write is the member record join will persist.
    {
        let _store = DurableStore::open(dir.path.clone(), drive, "test-pass").unwrap();
        write_member_custody(
            &dir.path,
            &identity.device_id(),
            &wrap_device_secret(encryption.as_bytes(), "test-pass").unwrap(),
        )
        .unwrap();
    }
    let engine = open_keystore(dir.path.clone(), "test-pass", identity.clone()).unwrap();
    assert_eq!(
        engine.device(),
        identity.device_id(),
        "the recorded device reopens"
    );
    assert!(
        engine.log.known_state().is_none(),
        "no membership observed yet"
    );
    // A wrong identity names no record here, and a wrong
    // passphrase fails the wrap open: both fail closed.
    let other = DeviceIdentitySecret::generate().unwrap();
    assert!(matches!(
        open_keystore(dir.path.clone(), "test-pass", other),
        Err(EngineError::DeviceMismatch)
    ));
    assert!(matches!(
        open_keystore(dir.path.clone(), "wrong-pass", identity),
        Err(EngineError::Keystore(_))
    ));
}

#[test]
fn malformed_member_custody_fails_closed() {
    let device = DeviceIdentitySecret::generate().unwrap().device_id();
    let wrapped = wrap_device_secret(
        DeviceEncryptionSecret::generate().unwrap().as_bytes(),
        "test-pass",
    )
    .unwrap();
    let mut record = encode_member_custody(&device, &wrapped);
    assert!(
        matches!(decode_custody(&record), Ok(Custody::Member { .. })),
        "the member record decodes"
    );
    record[0] = 0x01;
    assert!(matches!(
        decode_custody(&record),
        Err(EngineError::MalformedKeystore)
    ));
    record[0] = MEMBER_KEYSTORE_VERSION;
    record.pop();
    assert!(matches!(
        decode_custody(&record),
        Err(EngineError::MalformedKeystore)
    ));
}

#[test]
fn pairing_request_stages_once_and_reuses() {
    let dir = TestDir::new("pairing-request");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let first = pairing_request(&dir.path, "test-pass", &identity).unwrap();
    assert_eq!(first.device, identity.device_id());
    // Re-running returns the same key: the owner may already have
    // admitted it, so a fresh secret would strand the admission.
    let second = pairing_request(&dir.path, "test-pass", &identity).unwrap();
    assert_eq!(first, second, "pairing material is stable");
    // The staged wrap opens under the right passphrase only.
    assert!(matches!(
        pairing_request(&dir.path, "wrong-pass", &identity),
        Err(EngineError::Keystore(_))
    ));
}

#[test]
fn join_round_trip_reopens_as_member() {
    let owner_dir = TestDir::new("join-owner");
    let newcomer_dir = TestDir::new("join-newcomer");
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let newcomer_identity = DeviceIdentitySecret::generate().unwrap();
    let mut owner = create(owner_dir.path.clone(), "test-pass", owner_identity).unwrap();
    let pairing = pairing_request(&newcomer_dir.path, "test-pass", &newcomer_identity).unwrap();
    let invitation = owner
        .admit_device(pairing.device, pairing.encryption_key)
        .unwrap()
        .invitation;
    let joined = join(
        newcomer_dir.path.clone(),
        "test-pass",
        newcomer_identity.clone(),
        &invitation,
    )
    .unwrap();
    assert!(
        joined.log.known_state().is_some(),
        "join commits the invitation genesis"
    );
    drop(joined);
    // The joined device reopens from member custody with its
    // invited epochs held: restart-safe like the owner path.
    let reopened =
        open_keystore(newcomer_dir.path.clone(), "test-pass", newcomer_identity).unwrap();
    assert!(
        reopened.log.known_state().is_some(),
        "member custody reopens"
    );
    assert!(
        reopened.epoch_keys.contains_key(&1) && reopened.epoch_keys.contains_key(&2),
        "invited epochs reinstall from the pending record on reopen"
    );
}

#[test]
fn join_into_owner_directory_refuses_and_preserves_custody() {
    let dir = TestDir::new("join-owner-dir");
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let mut owner = create(dir.path.clone(), "test-pass", owner_identity.clone()).unwrap();
    let owner_keystore = std::fs::read(dir.path.join(KEYSTORE_FILE)).unwrap();
    // A pairing staged in the owner's own directory, admitted,
    // then joined there: the DRIVE check passes (same drive), so
    // only the custody guard stands between join and root loss.
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let pairing = pairing_request(&dir.path, "test-pass", &newcomer).unwrap();
    let invitation = owner
        .admit_device(pairing.device, pairing.encryption_key)
        .unwrap()
        .invitation;
    drop(owner);
    assert!(matches!(
        join(dir.path.clone(), "test-pass", newcomer, &invitation,),
        Err(EngineError::OwnerCustodyExists)
    ));
    assert_eq!(
        std::fs::read(dir.path.join(KEYSTORE_FILE)).unwrap(),
        owner_keystore,
        "a refused join leaves the owner keystore byte-identical"
    );
    drop(open_keystore(dir.path.clone(), "test-pass", owner_identity).unwrap());
}

#[test]
fn join_over_other_member_custody_refuses() {
    let dir = TestDir::new("join-other-member");
    let owner_identity = DeviceIdentitySecret::generate().unwrap();
    let owner_dir = TestDir::new("join-other-member-owner");
    let mut owner = create(owner_dir.path.clone(), "test-pass", owner_identity.clone()).unwrap();
    // First device joins normally.
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let pairing = pairing_request(&dir.path, "test-pass", &newcomer).unwrap();
    let admitted = owner
        .admit_device(pairing.device, pairing.encryption_key)
        .unwrap()
        .invitation;
    drop(join(dir.path.clone(), "test-pass", newcomer.clone(), &admitted).unwrap());
    // A second device stages over the same pairing file, then
    // attempts to join the occupied directory: the member record
    // names the first device, so the write refuses rather than
    // stranding it.
    let other = DeviceIdentitySecret::generate().unwrap();
    let other_encryption = DeviceEncryptionSecret::generate().unwrap();
    std::fs::write(
        dir.path.join(PAIRING_FILE),
        wrap_device_secret(other_encryption.as_bytes(), "test-pass")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let sealed = invitation(
        owner.drive,
        &owner_identity,
        &DeviceEncryptionSecret::generate().unwrap(),
        &other,
        &other_encryption,
        EpochSecret::generate().unwrap(),
    );
    assert!(matches!(
        join(dir.path.clone(), "test-pass", other, &sealed),
        Err(EngineError::DeviceMismatch)
    ));
    // The first device still reopens from its intact custody.
    drop(open_keystore(dir.path.clone(), "test-pass", newcomer).unwrap());
}

#[test]
fn join_with_foreign_invitation_refuses_before_writing_custody() {
    let dir = TestDir::new("join-foreign");
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    pairing_request(&dir.path, "test-pass", &newcomer).unwrap();
    // An invitation addressed to another key: the staged secret
    // cannot open it, so nothing may touch disk.
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let stranger = DeviceIdentitySecret::generate().unwrap();
    let stranger_encryption = DeviceEncryptionSecret::generate().unwrap();
    let sealed = invitation(
        drive_id(),
        &owner,
        &owner_encryption,
        &stranger,
        &stranger_encryption,
        EpochSecret::generate().unwrap(),
    );
    assert!(matches!(
        join(dir.path.clone(), "test-pass", newcomer, &sealed),
        Err(EngineError::Invitation(_))
    ));
    assert!(
        !dir.path.join(KEYSTORE_FILE).exists(),
        "a refused join writes no custody"
    );
}

/// Seal a genuine invitation: the owner admits nobody yet (the
/// admission transition arrives via catch-up), but grants the
/// invitee the epoch-1 secret bound to the genesis it anchors.
fn invitation(
    drive: DriveId,
    owner: &DeviceIdentitySecret,
    owner_encryption: &DeviceEncryptionSecret,
    invitee: &DeviceIdentitySecret,
    invitee_encryption: &DeviceEncryptionSecret,
    epoch: EpochSecret,
) -> crate::control::bootstrap::SealedBootstrap {
    let genesis = genesis_transition(drive, owner, owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![epoch],
    )
    .unwrap();
    seal_bootstrap(
        owner,
        &drive,
        invitee_id,
        &invitee_key,
        &genesis.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap()
}

fn drive_id() -> DriveId {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes).unwrap();
    DriveId::from_bytes(bytes)
}

#[test]
fn accept_invitation_installs_genesis_and_first_epoch_key() {
    let dir = TestDir::new("accept-invitation");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let epoch = EpochSecret::generate().unwrap();
    let sealed = invitation(
        drive,
        &owner,
        &owner_encryption,
        &invitee,
        &invitee_encryption,
        epoch.clone(),
    );

    let mut engine = Engine::accept_invitation(
        dir.path.clone(),
        "test-pass",
        invitee,
        invitee_encryption,
        &sealed,
    )
    .unwrap();
    assert_eq!(engine.drive, drive);
    assert!(
        engine.log.known_state().is_some(),
        "the invitation genesis is committed"
    );

    // Behavioral proof of the epoch key: a control message sealed
    // under the epoch-1 key drains instead of stalling as skipped.
    // KeyRotation is envelope-defined but unhandled, so it is the
    // cheapest accepted message with no chain to build.
    let rotation = Message::KeyRotation(KeyRotation {
        transition: TransitionId::from_bytes([0x31; 32]),
    });
    let sealed_msg = seal(&epoch.control_key(&drive, 1), &drive, 1, &rotation).unwrap();
    let mut relay = MemoryRelay::default();
    relay.push(seal_for_recipient(&owner, engine.device, &sealed_msg.encode()).unwrap());
    let mut mailbox = MemoryMailbox {
        relay: &mut relay,
        owner: engine.device,
    };
    let report = engine.drain(&mut mailbox).unwrap();
    assert_eq!(report.skipped, 0, "epoch-1 key opens the message");
    assert_eq!(report.accepted, 1, "the rotation is consumed");
}

#[test]
fn accept_invitation_for_another_device_is_refused() {
    let dir = TestDir::new("accept-invitation-mismatch");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let sealed = invitation(
        drive_id(),
        &owner,
        &owner_encryption,
        &invitee,
        &invitee_encryption,
        EpochSecret::generate().unwrap(),
    );

    let stranger = DeviceIdentitySecret::generate().unwrap();
    // The stranger holds the invitee's encryption secret, so the
    // seal opens — but the invitation names another device. (With a
    // wrong encryption secret the seal fails to open first, which
    // surfaces as `Invitation`, not a mismatch.)
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            stranger,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::InvitationMismatch)
    ));
}

#[test]
fn accept_invitation_sealed_to_a_substituted_key_is_refused() {
    // The seal names the victim device but wraps to an attacker's
    // encryption key: the victim's secret cannot open it, so accept
    // refuses before touching disk. The recipient key is
    // cryptographic, never advisory — a seal that opens under the
    // wrong key is no invitation at all.
    let dir = TestDir::new("accept-invitation-substituted-key");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let attacker_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let genesis = genesis_transition(drive, &owner, &owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![EpochSecret::generate().unwrap()],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &attacker_encryption.encryption_key(),
        &genesis.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::Invitation(_))
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "substituted-key invitations never touch disk"
    );
}

#[test]
fn per_transition_escrow_restores_later_epochs_from_root_alone() {
    // T13 mint-time integration: admitting a device (epoch 2)
    // writes an escrow sidecar at commit time, and root custody
    // alone restores the epoch-2 control key — no keyring, no
    // catch-up delivery.
    let dir = TestDir::new("per-transition-escrow");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner.clone()).unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(newcomer.device_id(), newcomer_encryption.encryption_key())
        .unwrap();
    let epoch2_key = engine
        .epoch_keys
        .get(&2)
        .cloned()
        .expect("authoring installs the fresh control key");
    // The sidecar exists on disk and decodes to epoch 2.
    let record = escrow::load_record(&dir.path, 2)
        .unwrap()
        .expect("mint writes the sidecar");
    assert_eq!(record.epoch, 2);
    // The shared tail covers the other authoring paths: rotate
    // through it and epoch 3 escrows the same way.
    engine.rotate_epoch().unwrap();
    let epoch3_key = engine
        .epoch_keys
        .get(&3)
        .cloned()
        .expect("rotation installs its control key");
    assert_eq!(
        escrow::load_record(&dir.path, 3)
            .unwrap()
            .expect("shared tail escrows every path")
            .epoch,
        3
    );
    drop(engine);
    // Reopen from keystore alone, then prove the escrow path —
    // not the keyring — restores the later epochs: remove the
    // keyring-derived keys and restore from the sidecars.
    let mut engine = Engine::open_keystore(dir.path.clone(), "test-pass", owner).unwrap();
    engine.epoch_keys.remove(&2);
    engine.epoch_keys.remove(&3);
    restore_escrowed_epochs(&mut engine).unwrap();
    assert_eq!(
        engine.epoch_keys.get(&2),
        Some(&epoch2_key),
        "root custody alone restores epoch 2"
    );
    assert_eq!(
        engine.epoch_keys.get(&3),
        Some(&epoch3_key),
        "root custody alone restores epoch 3"
    );
}

#[test]
fn escrow_restore_is_control_keys_only() {
    // T13 scope pin: the sidecar restore refills vacant epoch
    // control keys and does nothing else — it commits no durable
    // facts, so no keyring the facts authorize can change under
    // it. If a future guardian path installs unwrapped secrets
    // durably, this test fails until that path carries its own
    // authorization context and doc updates.
    //
    // Scope note: epoch 1 is the pre-existing exception. The
    // keystore custody record carries its own epoch-1 escrow, so
    // an owner open whose keyring lacks the genesis secret
    // reinstalls it through install_self_capability (idempotent:
    // present material wins, no rewrite); the sidecar restore
    // itself covers epochs 2+ only.
    let dir = TestDir::new("escrow-restore-control-keys-only");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner.clone()).unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(newcomer.device_id(), newcomer_encryption.encryption_key())
        .unwrap();
    let epoch2_key = engine
        .epoch_keys
        .get(&2)
        .cloned()
        .expect("authoring installs the fresh control key");
    engine.rotate_epoch().unwrap();
    let epoch3_key = engine
        .epoch_keys
        .get(&3)
        .cloned()
        .expect("rotation installs its control key");
    drop(engine);
    let mut engine = Engine::open_keystore(dir.path.clone(), "test-pass", owner).unwrap();
    let facts_before = engine.store.load().unwrap();
    // Vacate the later control keys, exactly like the sibling
    // restore test; the restore must refill them with the exact
    // keys, and change nothing else.
    engine.epoch_keys.remove(&2);
    engine.epoch_keys.remove(&3);
    restore_escrowed_epochs(&mut engine).unwrap();
    assert_eq!(
        engine.epoch_keys.get(&2),
        Some(&epoch2_key),
        "root custody alone restores epoch 2"
    );
    assert_eq!(
        engine.epoch_keys.get(&3),
        Some(&epoch3_key),
        "root custody alone restores epoch 3"
    );
    // Set-wise, not just point-wise: the restore refilled exactly
    // the vacated epochs — epoch 1 untouched, nothing else added.
    // This is the assertion behind the "epochs 2+ only" scope note.
    let held: Vec<u64> = engine.epoch_keys.keys().copied().collect();
    assert_eq!(held, vec![1, 2, 3], "restore covers exactly epochs 2+");
    // The no-install half: the durable facts are byte-identical
    // across the restore, so no keyring the facts authorize could
    // have changed under it either (keyring rebuilds are a pure
    // function of these facts).
    let facts_after = engine.store.load().unwrap();
    assert_eq!(
        facts_after, facts_before,
        "escrow restore commits nothing durable"
    );
}

#[test]
fn conflicting_escrow_sidecar_fails_owner_open_closed() {
    // A valid same-root sidecar holding a DIFFERENT secret for an
    // epoch the keyring covers: owner open fails with
    // EscrowConflict instead of silently running the durable
    // history on a replaced key. Escrow fills vacancies; it never
    // outranks held material.
    let dir = TestDir::new("conflicting-escrow");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner.clone()).unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    engine
        .admit_device(newcomer.device_id(), newcomer_encryption.encryption_key())
        .unwrap();
    let drive = engine.drive;
    // Forge the conflicting sidecar: unwrap the root from the
    // keystore and seal another epoch-2 secret under it.
    let Custody::Owner { root: wrapped, .. } = read_custody(&dir.path).expect("keystore exists")
    else {
        panic!("owner custody");
    };
    let root = DriveRootKey::from_bytes(unwrap_root(&wrapped, "test-pass").unwrap());
    let forged = escrow::wrap(
        &root.escrow_key(&drive, 2),
        &drive,
        2,
        &EpochSecret::generate().unwrap(),
    )
    .unwrap();
    escrow::persist_record(&dir.path, &forged).unwrap();
    drop(engine);
    assert!(matches!(
        Engine::open_keystore(dir.path.clone(), "test-pass", owner),
        Err(EngineError::EscrowConflict(2))
    ));
}

#[test]
fn failed_escrow_persist_heals_on_next_authoring() {
    // Fault injection for the commit-then-escrow window: a file
    // where the sidecar directory must go (fails under any uid,
    // unlike permission bits). The admission commits — epoch 2 is
    // durable — but the escrow persist fails loudly, leaving the
    // degraded state: committed epoch, no recovery record. The
    // next authoring backfills the missing sidecar from the
    // keyring and writes its own, so the hole heals instead of
    // lasting forever.
    let dir = TestDir::new("escrow-backfill");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner.clone()).unwrap();
    std::fs::write(dir.path.join(escrow::ESCROW_DIR), b"blocker").unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    let newcomer_encryption = DeviceEncryptionSecret::generate().unwrap();
    assert!(matches!(
        engine.admit_device(newcomer.device_id(), newcomer_encryption.encryption_key()),
        Err(EngineError::Io(_))
    ));
    assert_eq!(
        engine.log.known_state().map(|known| known.epoch),
        Some(2),
        "the transition commits before the escrow fails"
    );
    assert!(
        !escrow::record_path(&dir.path, 2).exists(),
        "no sidecar: the degraded recovery state"
    );
    // Heal the fault and author again: epoch 2 backfills from the
    // keyring, epoch 3 writes fresh.
    std::fs::remove_file(dir.path.join(escrow::ESCROW_DIR)).unwrap();
    engine.rotate_epoch().unwrap();
    let epoch2_key = engine.epoch_keys.get(&2).cloned().expect("held");
    let epoch3_key = engine.epoch_keys.get(&3).cloned().expect("held");
    assert_eq!(
        escrow::load_record(&dir.path, 2)
            .unwrap()
            .expect("backfilled")
            .epoch,
        2
    );
    assert_eq!(
        escrow::load_record(&dir.path, 3)
            .unwrap()
            .expect("fresh")
            .epoch,
        3
    );
    drop(engine);
    // Both epochs restore from root custody alone.
    let mut engine = Engine::open_keystore(dir.path.clone(), "test-pass", owner).unwrap();
    engine.epoch_keys.remove(&2);
    engine.epoch_keys.remove(&3);
    restore_escrowed_epochs(&mut engine).unwrap();
    assert_eq!(engine.epoch_keys.get(&2), Some(&epoch2_key));
    assert_eq!(engine.epoch_keys.get(&3), Some(&epoch3_key));
}

#[test]
fn accept_invitation_with_invalid_genesis_is_refused_before_disk() {
    let dir = TestDir::new("accept-invitation-tampered");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let epoch = EpochSecret::generate().unwrap();

    // A well-formed but invalid genesis: correctly signed by the
    // owner, undecodable roots. The envelope signature covers
    // arbitrary bytes, so this opens — validation must still refuse
    // it.
    let mut bad = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![Change::Admit(Admission {
            device: owner.device_id(),
            encryption_key: owner_encryption.encryption_key(),
        })],
        [0xFF; 32],
        [0xFF; 32],
        [0xFF; 32],
        owner.device_id(),
    )
    .unwrap();
    sign_transition(&mut bad, &owner.secret_key(), &drive);
    let genesis_id = genesis_transition(drive, &owner, &owner_encryption)
        .unwrap()
        .transition_id();
    let capability = Capability::new(
        drive,
        invitee_id,
        invitee_key,
        genesis_id,
        1,
        vec![epoch.clone()],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        &bad.canonical_bytes(),
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee.clone(),
            invitee_encryption.clone(),
            &sealed
        ),
        Err(EngineError::BadGenesis)
    ));

    // Undecodable genesis bytes fail the same gate.
    let sealed_garbage = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        b"not a transition",
        capability.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed_garbage
        ),
        Err(EngineError::BadGenesis)
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "invalid invitations never touch disk"
    );
}

#[test]
fn accept_invitation_with_foreign_capability_is_refused() {
    let dir = TestDir::new("accept-invitation-foreign");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let owner_encryption = DeviceEncryptionSecret::generate().unwrap();
    let invitee = DeviceIdentitySecret::generate().unwrap();
    let invitee_encryption = DeviceEncryptionSecret::generate().unwrap();
    let drive = drive_id();
    let genesis = genesis_transition(drive, &owner, &owner_encryption).unwrap();
    let invitee_id = invitee.device_id();
    let invitee_key = invitee_encryption.encryption_key();
    let epoch = EpochSecret::generate().unwrap();

    // A structurally valid grant for another drive: it unwraps
    // under our secret (ECDH binds the recipient, not the drive),
    // so only the explicit drive cross-check refuses it before its
    // secrets become our control keys.
    let foreign = Capability::new(
        drive_id(),
        invitee_id,
        invitee_key,
        genesis.transition_id(),
        1,
        vec![epoch],
    )
    .unwrap();
    let sealed = seal_bootstrap(
        &owner,
        &drive,
        invitee_id,
        &invitee_key,
        &genesis.canonical_bytes(),
        foreign.wrap().unwrap().as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        Engine::accept_invitation(
            dir.path.clone(),
            "test-pass",
            invitee,
            invitee_encryption,
            &sealed
        ),
        Err(EngineError::InvitationMismatch)
    ));
    assert!(
        !dir.path.join("DRIVE").exists(),
        "foreign grants never touch disk"
    );
}

#[test]
fn resync_refuses_bootstrap_that_disagrees_with_the_keyring() {
    let dir = TestDir::new("bootstrap-conflict");
    let owner = DeviceIdentitySecret::generate().unwrap();
    let mut engine = Engine::create(dir.path.clone(), "test-pass", owner).unwrap();
    let drive = engine.drive;
    let genesis_id = engine
        .log
        .known_state()
        .map(|state| state.transition_id)
        .expect("creation commits genesis");
    let self_cap = engine
        .store
        .load()
        .unwrap()
        .capabilities
        .into_iter()
        .find(|cap| cap.device == engine.device)
        .expect("creation commits a self capability");
    let held_before = engine
        .epoch_keys
        .get(&1)
        .cloned()
        .expect("escrow installs the epoch-1 key");

    // A self-addressed wrap carrying a different epoch-1 secret,
    // committed as a pending blob: the only way bootstrap material
    // can disagree with the authorized keyring is a buggy or
    // malicious inviter, so resync must fail closed, never swap.
    let fake = Capability::new(
        drive,
        engine.device,
        self_cap.encryption_key,
        genesis_id,
        1,
        vec![EpochSecret::generate().unwrap()],
    )
    .unwrap();
    engine
        .commit_facts(&[Fact::BootstrapPending(
            fake.wrap().unwrap().as_bytes().to_vec(),
        )])
        .unwrap();
    let err = engine.resync().unwrap_err();
    assert!(
        matches!(err, EngineError::BootstrapKeyConflict(1)),
        "unexpected: {err:?}"
    );
    assert_eq!(
        engine.epoch_keys.get(&1),
        Some(&held_before),
        "a conflicting blob installs nothing"
    );
}
