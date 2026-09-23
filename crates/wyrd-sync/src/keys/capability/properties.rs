//! Property tests for capability installation: the nine adversarial
//! cases from the fuzz-capability issue, in randomized orderings.
//!
//! `DriveKeyring::install` is example-tested in `tests.rs`; these assert
//! the state machine instead: after ANY sequence of installs — old,
//! current, future-bound, duplicated, conflicting, and misdirected —
//! the held secrets are exactly the newest valid capability for this
//! device and drive, never older, never swapped, never foreign. Every
//! capability covers `1..=N` contiguously by construction, so the held
//! set is always a full prefix `1..=M`; the model below tracks that
//! prefix and every install must agree with it or fail leaving state
//! untouched.
//!
//! Layering note: `install` takes an unwrapped `Capability`, so there
//! is no AEAD here — recipient binding at this layer is the
//! drive/device gates plus `authorize_against` (registered key,
//! transition, epoch). The ECDH recipient proof lives one layer down
//! in wrap/unwrap (pinned by the wrap proptest and the intake
//! foreign-wrap test); the wrong-device case here carries otherwise
//! valid minted material to prove installation itself refuses it.

use std::collections::BTreeMap;

use proptest::prelude::*;
use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId, TransitionId};

use super::model::{Capability, CapabilityError, DriveKeyring, InstallError, InstallReport};
use crate::keys::epoch::EpochSecret;
use crate::membership::test_util::{admit, key, Builder};
use crate::membership::MembershipLog;

/// Fixed secrets: determinism keeps proptest shrinking useful (no
/// randomness inside the test body).
fn secret(pattern: u8) -> EpochSecret {
    EpochSecret::from_bytes([pattern; 32])
}

/// The pool operand: one of the eight capability shapes. The ninth
/// issue case (duplicates/replays) and every ordering (old-after-new,
/// conflict-before-valid, …) come from the generated index sequences,
/// not the pool.
struct Pool {
    /// Valid cap for A bound to the epoch-2 admission (`[s1, s2]`).
    old: Capability,
    /// Valid cap for A bound to the epoch-3 admission (`[s1, s2, s3]`).
    new: Capability,
    /// Same binding as `new`, epoch-2 secret swapped.
    conflict_e2: Capability,
    /// Same binding as `new`, epoch-3 secret swapped.
    conflict_e3: Capability,
    /// Fully valid material minted for B, not A.
    foreign_device: Capability,
    /// Bound to an unobserved transition (future binding).
    future_binding: Capability,
    /// Valid binding, wrong drive.
    foreign_drive: Capability,
    /// Valid binding, attacker's encryption key.
    foreign_key: Capability,
}

struct Rig {
    log: MembershipLog,
    drive: DriveId,
    device_a: DeviceId,
    pool: Pool,
}

fn rig() -> Rig {
    let (mut b, genesis) = Builder::genesis(10);
    let (_, a) = key(20);
    let (_, other) = key(21);
    let t2 = b.child(vec![admit(a)]);
    let t3 = b.child(vec![admit(other)]);
    let mut log = MembershipLog::new(b.drive);
    log.observe(genesis);
    log.observe(t2.clone());
    log.observe(t3.clone());
    let drive = b.drive;
    let s1 = secret(0xA1);
    let s2 = secret(0xA2);
    let s3 = secret(0xA3);
    let state2 = log.state_of(&t2.transition_id()).expect("t2 valid");
    let state3 = log.state_of(&t3.transition_id()).expect("t3 valid");
    let old =
        Capability::mint(drive, a, &state2, &t2, vec![s1.clone(), s2.clone()]).expect("A admitted");
    let new = Capability::mint(
        drive,
        a,
        &state3,
        &t3,
        vec![s1.clone(), s2.clone(), s3.clone()],
    )
    .expect("A member");
    let mut conflict_e2 = new.clone();
    conflict_e2.secrets[1] = secret(0xE2);
    let mut conflict_e3 = new.clone();
    conflict_e3.secrets[2] = secret(0xE3);
    let foreign_device = Capability::mint(
        drive,
        other,
        &state3,
        &t3,
        vec![s1.clone(), s2.clone(), s3.clone()],
    )
    .expect("B admitted");
    let registered_a = state3.encryption_key_of(&a).copied().expect("A key");
    let future_binding = Capability::new(
        drive,
        a,
        registered_a,
        TransitionId::from_bytes([0xF0; 32]),
        3,
        vec![s1.clone(), s2.clone(), s3.clone()],
    )
    .expect("shape valid");
    let mut foreign_drive = new.clone();
    foreign_drive.drive = DriveId::from_bytes([0xDD; 32]);
    let attacker_key = DeviceEncryptionKey::from_bytes(*key(99).1.as_bytes());
    let foreign_key = Capability::new(
        drive,
        a,
        attacker_key,
        t3.transition_id(),
        3,
        vec![s1.clone(), s2.clone(), s3],
    )
    .expect("shape valid");
    Rig {
        log,
        drive,
        device_a: a,
        pool: Pool {
            old,
            new,
            conflict_e2,
            conflict_e3,
            foreign_device,
            future_binding,
            foreign_drive,
            foreign_key,
        },
    }
}

fn operand(pool: &Pool, index: u8) -> &Capability {
    match index {
        0 => &pool.old,
        1 => &pool.new,
        2 => &pool.conflict_e2,
        3 => &pool.conflict_e3,
        4 => &pool.foreign_device,
        5 => &pool.future_binding,
        6 => &pool.foreign_drive,
        _ => &pool.foreign_key,
    }
}

proptest! {
    /// Adversarial installation orderings: any sequence over the eight
    /// shapes must keep the keyring exactly at the newest valid
    /// capability for this device/drive. Valid installs fill the held
    /// prefix forward (duplicates and old-after-new are no-ops);
    /// conflicts and misdirected capabilities fail without moving
    /// state. The per-step model assert subsumes monotonicity: held
    /// values are immutable once set, and the set only grows.
    #[test]
    fn installation_orderings_keep_the_newest_valid_capability(
        sequence in prop::collection::vec(0..8u8, 1..24usize),
    ) {
        let rig = rig();
        let mut keyring = DriveKeyring::new(rig.drive, rig.device_a);
        // Model: the held prefix, epoch -> secret. Every installable
        // capability covers 1..=N contiguously, so this stays a full
        // 1..=M prefix by construction.
        let mut expected: BTreeMap<u64, EpochSecret> = BTreeMap::new();

        for index in sequence {
            let cap = operand(&rig.pool, index);
            let before: BTreeMap<u64, EpochSecret> = (1..=3)
                .filter_map(|e| keyring.secret(e).cloned().map(|s| (e, s)))
                .collect();
            prop_assert_eq!(&before, &expected, "keyring tracks the model");

            // The model verdict for this operand against the held prefix.
            enum Verdict {
                Fill,
                Conflict(u64),
                Refused,
            }
            let verdict = match index {
                0 | 1 => {
                    let mut conflict = None;
                    for (i, s) in cap.secrets.iter().enumerate() {
                        let epoch = i as u64 + 1;
                        if let Some(held) = expected.get(&epoch) {
                            if held != s {
                                conflict = Some(epoch);
                                break;
                            }
                        }
                    }
                    match conflict {
                        Some(epoch) => Verdict::Conflict(epoch),
                        None => Verdict::Fill,
                    }
                }
                2 | 3 => {
                    // Same rule: a conflicting shape installs cleanly
                    // into a vacant keyring and only conflicts once
                    // the epoch it disagrees about is held.
                    let mut conflict = None;
                    for (i, s) in cap.secrets.iter().enumerate() {
                        let epoch = i as u64 + 1;
                        if let Some(held) = expected.get(&epoch) {
                            if held != s {
                                conflict = Some(epoch);
                                break;
                            }
                        }
                    }
                    match conflict {
                        Some(epoch) => Verdict::Conflict(epoch),
                        None => Verdict::Fill,
                    }
                }
                _ => Verdict::Refused,
            };

            match verdict {
                Verdict::Fill => {
                    let from = expected.len() as u64 + 1;
                    let to = cap.secrets.len() as u64;
                    let report = keyring.install(cap, &rig.log);
                    if from > to {
                        prop_assert_eq!(report, Ok(InstallReport::NoChange));
                    } else {
                        prop_assert_eq!(report, Ok(InstallReport::Added { from, to }));
                        for epoch in from..=to {
                            expected.insert(epoch, cap.secrets[epoch as usize - 1].clone());
                        }
                    }
                }
                Verdict::Conflict(epoch) => {
                    prop_assert_eq!(
                        keyring.install(cap, &rig.log),
                        Err(InstallError::EpochConflict(epoch))
                    );
                }
                Verdict::Refused => {
                    let result = keyring.install(cap, &rig.log);
                    match index {
                        4 => prop_assert!(matches!(
                            result,
                            Err(InstallError::WrongDevice(..))
                        )),
                        5 => prop_assert!(matches!(
                            result,
                            Err(InstallError::Unauthorized(
                                CapabilityError::UnknownTransition(_)
                            ))
                        )),
                        6 => prop_assert!(matches!(
                            result,
                            Err(InstallError::WrongDrive(..))
                        )),
                        _ => prop_assert!(matches!(
                            result,
                            Err(InstallError::Unauthorized(
                                CapabilityError::StaleEncryptionKey
                            ))
                        )),
                    }
                }
            }

            let after: BTreeMap<u64, EpochSecret> = (1..=3)
                .filter_map(|e| keyring.secret(e).cloned().map(|s| (e, s)))
                .collect();
            match verdict {
                Verdict::Fill => prop_assert_eq!(&after, &expected),
                _ => prop_assert_eq!(&after, &before, "failures move no state"),
            }
        }

        // Final state: exactly the newest valid capability seen —
        // every held epoch present, nothing foreign, prefix-complete.
        let held: BTreeMap<u64, EpochSecret> = (1..=3)
            .filter_map(|e| keyring.secret(e).cloned().map(|s| (e, s)))
            .collect();
        prop_assert_eq!(&held, &expected);
        if let Some(max) = expected.keys().next_back() {
            prop_assert_eq!(held.len() as u64, *max, "held set is a full prefix");
        }
    }
}
