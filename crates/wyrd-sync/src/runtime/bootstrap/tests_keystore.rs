use super::keystore::{
    decode_custody, encode_custody, encode_member_custody, read_custody, restore_escrowed_epochs,
    write_member_custody, Custody, KEYSTORE_FILE, MEMBER_KEYSTORE_VERSION,
};
use super::*;
use crate::durable::{atomic_write_mode, DurableError, DurableStore, SECRET_FILE_MODE};
use crate::keys::keystore::{unwrap_root, wrap_device_secret, wrap_root};
use crate::keys::{escrow, random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::keys::{DriveRootKey, EpochSecret};
use crate::runtime::engine::{Engine, EngineError};
use crate::runtime::test_util::TestDir;
use wyrd_format::DriveId;

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
        atomic_write_mode(&dir.path, KEYSTORE_FILE, &custody, SECRET_FILE_MODE).unwrap();
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
    // Release the lock before probing mismatches: the open acquires
    // the store lock before reading custody, so a held lock reports
    // contention before identity is even compared.
    drop(engine);
    // A wrong identity names no record here, and a wrong
    // passphrase fails the wrap open: both fail closed.
    let other = DeviceIdentitySecret::generate().unwrap();
    assert!(matches!(
        open_keystore(dir.path.clone(), "test-pass", other),
        Err(EngineError::DeviceMismatch)
    ));
    // Same lock-first precedence as the owner path: the store key
    // unwrap runs before the custody unwrap.
    assert!(matches!(
        open_keystore(dir.path.clone(), "wrong-pass", identity),
        Err(EngineError::Durable(DurableError::StoreKey(_)))
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
fn swapped_custody_record_fails_closed_on_open() {
    let victim = TestDir::new("custody-swap-victim");
    let owner = DeviceIdentitySecret::generate().unwrap();
    drop(create(victim.path.clone(), "test-pass", owner.clone()).unwrap());

    // An attacker record that unwraps under the same passphrase but
    // names a different owner: a well-formed owner custody from a
    // second drive. Copying it over the victim pins custody
    // interpretation (the open proceeds on the bytes on disk and fails
    // closed on them); the lock ordering itself is pinned by the
    // lock-first error precedence elsewhere, since a sequential test
    // cannot land inside the old read-then-lock window.
    let attacker_dir = TestDir::new("custody-swap-attacker");
    let attacker = DeviceIdentitySecret::generate().unwrap();
    drop(create(attacker_dir.path.clone(), "test-pass", attacker.clone()).unwrap());
    let attacker_record =
        std::fs::read(attacker_dir.path.join(KEYSTORE_FILE)).expect("attacker has custody");
    std::fs::write(victim.path.join(KEYSTORE_FILE), &attacker_record).unwrap();

    // The open must proceed on the bytes on disk at open time — the
    // swapped record — and fail closed on them, never on stale bytes.
    // The victim identity no longer names the recorded owner, and the
    // attacker identity's escrow is bound to the attacker's drive, so
    // both fail; neither opens the victim's drive.
    assert!(
        matches!(
            open_keystore(victim.path.clone(), "test-pass", owner),
            Err(EngineError::OwnerMismatch)
        ),
        "a swapped record must not open under the victim identity"
    );
    assert!(
        matches!(
            open_keystore(victim.path.clone(), "test-pass", attacker),
            Err(EngineError::Crypto(_))
        ),
        "a swapped record must not open under the attacker identity either"
    );
}

#[test]
fn open_keystore_against_a_held_lock_reports_contention() {
    let dir = TestDir::new("custody-lock-held");
    let identity = DeviceIdentitySecret::generate().unwrap();
    let engine = create(dir.path.clone(), "test-pass", identity.clone()).unwrap();
    // Another holder owns the directory: the open must report
    // contention before it interprets any custody.
    let drive = engine.drive;
    drop(engine);
    let _holder = DurableStore::open(dir.path.clone(), drive, "test-pass").expect("holder opens");
    assert!(
        matches!(
            open_keystore(dir.path.clone(), "test-pass", identity),
            Err(EngineError::Durable(DurableError::StoreLocked))
        ),
        "a lock-held open reports contention, not custody"
    );
}

#[test]
fn open_on_a_drive_only_directory_writes_nothing() {
    // The crash window inside the store open between the DRIVE write
    // and the store-key write: DRIVE exists, nothing else does. The
    // open must refuse without minting state of its own.
    let dir = TestDir::new("custody-drive-only");
    let identity = DeviceIdentitySecret::generate().unwrap();
    std::fs::write(dir.path.join("DRIVE"), drive_id().as_bytes()).unwrap();
    assert!(
        open_keystore(dir.path.clone(), "test-pass", identity).is_err(),
        "a DRIVE-only directory refuses the open"
    );
    for residue in ["store-key.wrap", "LOCK", "commits", KEYSTORE_FILE] {
        assert!(
            !dir.path.join(residue).exists(),
            "the refused open leaves no {residue} behind"
        );
    }
}

#[test]
fn open_with_a_directory_named_keystore_writes_nothing() {
    // `metadata` succeeds on a directory, so the probe must also
    // require a file: a hand-crafted directory named `keystore` is
    // refused before the store open, minting nothing.
    let dir = TestDir::new("custody-keystore-dir");
    let identity = DeviceIdentitySecret::generate().unwrap();
    std::fs::write(dir.path.join("DRIVE"), drive_id().as_bytes()).unwrap();
    std::fs::create_dir(dir.path.join(KEYSTORE_FILE)).unwrap();
    assert!(
        matches!(
            open_keystore(dir.path.clone(), "test-pass", identity),
            Err(EngineError::MalformedKeystore)
        ),
        "a directory named keystore is not a custody record"
    );
    assert!(
        !dir.path.join("store-key.wrap").exists(),
        "the refused open mints no store key"
    );
}

// --- custody file modes ------------------------------------------------------
// Unix-only: POSIX modes are the guarantee under test.

#[cfg(unix)]
use crate::runtime::test_util::{file_mode as mode_of, UmaskGuard};

#[cfg(unix)]
#[test]
fn keystore_is_not_group_or_world_readable() {
    let mut modes = Vec::new();
    for mask in [0o000, 0o077] {
        let _guard = UmaskGuard::set(mask);
        let dir = TestDir::new("custody-keystore-mode");
        let identity = DeviceIdentitySecret::generate().unwrap();
        drop(create(dir.path.clone(), "test-pass", identity).unwrap());
        drop(_guard);
        let mode = mode_of(&dir.path.join(KEYSTORE_FILE));
        assert_eq!(mode & 0o077, 0, "umask {mask:03o}: {mode:03o}");
        modes.push(mode);
    }
    assert_eq!(modes[0], modes[1], "the mode is chosen, not umask-derived");
}
