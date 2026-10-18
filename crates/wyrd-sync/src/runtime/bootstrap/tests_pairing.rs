use super::keystore::KEYSTORE_FILE;
use super::pairing::PAIRING_FILE;
use super::*;
use crate::keys::keystore::wrap_device_secret;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret, EpochSecret};
use crate::runtime::engine::EngineError;
use crate::runtime::test_util::TestDir;
#[cfg(unix)]
use crate::runtime::test_util::{file_mode as mode_of, UmaskGuard};

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

#[cfg(unix)]
#[test]
fn pairing_secret_is_not_group_or_world_readable() {
    let mut modes = Vec::new();
    for mask in [0o000, 0o077] {
        let _guard = UmaskGuard::set(mask);
        let dir = TestDir::new("custody-pairing-mode");
        let identity = DeviceIdentitySecret::generate().unwrap();
        pairing_request(&dir.path, "test-pass", &identity).unwrap();
        drop(_guard);
        let mode = mode_of(&dir.path.join(PAIRING_FILE));
        assert_eq!(mode & 0o077, 0, "umask {mask:03o}: {mode:03o}");
        modes.push(mode);
    }
    assert_eq!(modes[0], modes[1], "the mode is chosen, not umask-derived");
}

#[cfg(unix)]
#[test]
fn a_lost_pairing_race_leaves_the_winners_file_at_the_hardened_mode() {
    use std::sync::Barrier;
    let _guard = UmaskGuard::set(0o000);
    let dir = TestDir::new("custody-pairing-race");
    let barrier = std::sync::Arc::new(Barrier::new(2));
    // Two concurrent stagings race the same `create_new`: exactly one
    // wins and the loser reuses the winner's wrap. Either order must
    // land an owner-only file.
    let run = |dir: std::path::PathBuf, barrier: std::sync::Arc<Barrier>| {
        std::thread::spawn(move || {
            barrier.wait();
            let identity = DeviceIdentitySecret::generate().unwrap();
            for _ in 0..1000 {
                match pairing_request(&dir, "test-pass", &identity) {
                    Ok(request) => return request,
                    // The winner may still be writing its wrap: retry
                    // until the staged file is complete.
                    Err(_) => std::thread::yield_now(),
                }
            }
            panic!("pairing_request never completed against a finished winner");
        })
    };
    let first = run(dir.path.clone(), barrier.clone());
    let second = run(dir.path.clone(), barrier);
    let (a, b) = (first.join().unwrap(), second.join().unwrap());
    drop(_guard);
    assert_ne!(a.device, b.device, "the two racers are distinct devices");
    assert_eq!(
        mode_of(&dir.path.join(PAIRING_FILE)) & 0o077,
        0,
        "the winner's file is owner-only under umask 000"
    );
}

#[cfg(unix)]
#[test]
fn pairing_request_leaves_an_established_drive_directory_alone() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = UmaskGuard::set(0o077);
    let dir = TestDir::new("custody-pairing-established");
    let identity = DeviceIdentitySecret::generate().unwrap();
    drop(create(dir.path.clone(), "test-pass", identity).unwrap());
    drop(_guard);
    // A pre-fix drive whose directory is still group-readable: staging
    // a pairing secret must change no directory mode.
    std::fs::set_permissions(&dir.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let newcomer = DeviceIdentitySecret::generate().unwrap();
    pairing_request(&dir.path, "test-pass", &newcomer).unwrap();
    assert_eq!(
        mode_of(&dir.path) & 0o777,
        0o755,
        "pairing-request touches no directory mode"
    );
}
