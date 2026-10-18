//! Custody (trust.md T2, T6, T8, T13, T14) is one atomically written
//! record, `<dir>/keystore`, so a crash can never leave part of it:
//!
//! ```text
//! root       DriveRootKey, wrapped under the passphrase (root domain)
//! device     device encryption secret, wrapped under the passphrase
//!            (device domain); the capability-ECDH target
//! escrow-1   epoch-1 secret, escrowed under the root (T13)
//! ```
//!
//! The Nostr identity secret is deliberately absent: it is the
//! caller/signer's key and is supplied on every open (T6, NIP-46).
//!
//! Creation acquires the durable store lock before it writes the drive
//! marker or any custody state, so two concurrent creators cannot
//! clobber each other: exactly one wins, the other sees `StoreLocked`.
//! Opening acquires the same lock before it reads the custody record,
//! so a cooperating writer cannot swap the record between the read and
//! the open. The lock serializes cooperating local callers only: the
//! local store is cooperative, and custody interpretation still fails
//! closed (identity, passphrase, and drive binding are all verified)
//! against a non-cooperating filesystem writer.

use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use wyrd_format::membership::{
    set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceId, DriveId, MembershipTransition};

use super::super::engine::{Engine, EngineError};
use crate::durable::{
    atomic_write_mode, ensure_owner_only_dir, AuthorizedCapability, DurableStore, Fact,
    SECRET_FILE_MODE,
};
use crate::keys::capability::Capability;
use crate::keys::keystore::{
    unwrap_device_secret, unwrap_root, wrap_device_secret, wrap_root, WrappedSecret,
};
use crate::keys::{
    escrow, random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey, EpochSecret,
};
use crate::membership::sign_transition;

/// The custody record file inside a drive directory.
pub(super) const KEYSTORE_FILE: &str = "keystore";

/// The only custody-record version.
const KEYSTORE_VERSION: u8 = 0x02;

/// The member custody-record version: a joined device's store carries
/// its own encryption secret and nothing else — no root, no escrow.
/// Members never hold either; epoch keys re-derive from the pending
/// invitation on every resync.
pub(super) const MEMBER_KEYSTORE_VERSION: u8 = 0x03;

/// Create a new single-device drive. `identity` is the owner's Nostr
/// identity (the signer's key, T6); everything else is generated and
/// persisted under `passphrase`. Fails if the directory already holds a
/// drive, so creation never clobbers one. On any failure the call rolls
/// back what it created.
pub(in crate::runtime) fn create(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    if dir.join("DRIVE").exists() {
        return Err(EngineError::DriveExists);
    }
    let encryption = DeviceEncryptionSecret::generate()?;
    let root = DriveRootKey::generate()?;
    let epoch = EpochSecret::generate()?;

    let mut drive_bytes = [0u8; 32];
    random_bytes(&mut drive_bytes)?;
    let drive = DriveId::from_bytes(drive_bytes);
    let device = identity.device_id();
    let genesis = genesis_transition(drive, &identity, &encryption)?;

    // Seal the custody record before the drive is usable. A crash before
    // the genesis commit is recoverable: `open_keystore` completes the
    // deterministic, owner-verified genesis.
    let custody = encode_custody(
        &device,
        &wrap_root(root.as_bytes(), passphrase)?,
        &wrap_device_secret(encryption.as_bytes(), passphrase)?,
        &escrow::wrap(&root.escrow_key(&drive, 1), &drive, 1, &epoch)?,
    );

    let dir_created = !dir.exists();
    ensure_owner_only_dir(&dir)?;

    // Acquire exclusive ownership before writing any drive or custody
    // state. This is the authoritative concurrency guard: the `DRIVE`
    // check above is only a friendly fast path. A failure here (contention
    // or an existing drive) means the state is somebody else's, so it is
    // deliberately outside the rollback below.
    let store = DurableStore::open(dir.clone(), drive, passphrase)?;
    if read_drive(&dir)? != drive {
        return Err(EngineError::DriveExists);
    }

    // From here the fresh store is ours. A crash between the custody
    // write and the genesis commit resumes on the next open: the genesis
    // is deterministic and owner-verified.
    let result = (|| -> Result<Engine, EngineError> {
        let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
        // Owner custody: the engine retains the root so later
        // authoring can escrow each fresh epoch secret at mint time
        // (T13). Member engines never hold it.
        engine.root = Some(root);
        atomic_write_mode(&dir, KEYSTORE_FILE, &custody, SECRET_FILE_MODE)?;
        engine.commit_facts(&[Fact::Transition(genesis.clone())])?;
        engine.resync()?;
        engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));
        install_self_capability(&mut engine, &genesis, &epoch)?;
        Ok(engine)
    })();

    match result {
        Ok(engine) => Ok(engine),
        Err(error) => {
            rollback(&dir, dir_created);
            Err(error)
        }
    }
}

/// Open a drive created by [`create`]: the drive id comes from the store
/// directory, the encryption secret and root are unwrapped from the
/// custody record, and the epoch-1 secret is un-escrowed under the root.
/// The caller supplies the identity secret (the signer's key).
///
/// A member custody record reopens the same way minus root and escrow:
/// the encryption secret unwraps from the record and epoch keys
/// re-derive from the pending invitation on resync, so a joined device
/// reopens with exactly what it held before the restart.
pub(in crate::runtime) fn open_keystore(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    // DRIVE is written once under the store lock and never changes
    // drives, so reading it pre-lock is a fast path only: the store
    // open below re-verifies it under the lock (`DriveMismatch` on
    // divergence).
    let drive = read_drive(&dir)?;
    // Refuse a missing custody record BEFORE opening the store: the
    // store open would mint `store-key.wrap` (plus `commits/` and
    // `LOCK`) in a directory this call is about to refuse, stranding a
    // crash-window directory no later open can use. A missing record
    // cannot become this caller's record, so the probe costs nothing
    // and reintroduces no race — only the *read* must sit under the
    // lock, not this existence check. Errors (including NotFound)
    // surface exactly as the pre-lock read produced them.
    match std::fs::metadata(dir.join(KEYSTORE_FILE)) {
        Ok(meta) if meta.is_file() => {}
        // A directory (or other non-file) named `keystore` is not a
        // record either: refuse before the store open mints state, the
        // same write-nothing guarantee the missing case has.
        Ok(_) => return Err(EngineError::MalformedKeystore),
        Err(error) => return Err(EngineError::Io(error)),
    }
    // Acquire the store lock BEFORE reading custody. Creation holds
    // this lock across the custody write, so no cooperating writer can
    // replace the record between this read and the engine open below:
    // the bytes decoded here are serialized against writers. The lock
    // guards cooperating callers only (see the module docs for the
    // threat model); a non-cooperating swap still fails closed, every
    // custody field being verified against the identity, the
    // passphrase, and the drive before the engine opens.
    let store = DurableStore::open(dir.clone(), drive, passphrase)?;
    match read_custody(&dir)? {
        Custody::Owner {
            owner,
            root: root_wrapped,
            device: device_wrapped,
            escrow: escrow_record,
        } => open_owner_keystore_with_store(
            store,
            drive,
            passphrase,
            identity,
            owner,
            root_wrapped,
            device_wrapped,
            escrow_record,
        ),
        Custody::Member {
            device: recorded,
            device_secret,
        } => {
            let device = identity.device_id();
            if device != recorded {
                return Err(EngineError::DeviceMismatch);
            }
            let encryption = DeviceEncryptionSecret::from_bytes(unwrap_device_secret(
                &device_secret,
                passphrase,
            )?)?;
            let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
            engine.resync()?;
            Ok(engine)
        }
    }
}

/// The owner half of [`open_keystore`]: root and epoch-1 escrow unwrap,
/// the deterministic genesis completes an interrupted bootstrap, and
/// the self capability installs exactly the escrowed epoch. Takes the
/// already-open store: the caller holds the lock across the custody
/// read, so this never re-opens (and never re-locks) the directory.
#[allow(clippy::too_many_arguments)]
fn open_owner_keystore_with_store(
    store: DurableStore,
    drive: DriveId,
    passphrase: &str,
    identity: DeviceIdentitySecret,
    owner: DeviceId,
    root_wrapped: WrappedSecret,
    device_wrapped: WrappedSecret,
    escrow_record: escrow::EscrowRecord,
) -> Result<Engine, EngineError> {
    let device = identity.device_id();
    if device != owner {
        return Err(EngineError::OwnerMismatch);
    }
    let encryption =
        DeviceEncryptionSecret::from_bytes(unwrap_device_secret(&device_wrapped, passphrase)?)?;
    let root = DriveRootKey::from_bytes(unwrap_root(&root_wrapped, passphrase)?);
    let epoch = escrow::unwrap(&root.escrow_key(&drive, 1), &escrow_record)?;

    // The genesis is a deterministic function of the (drive, owner,
    // encryption) triple, used to complete an interrupted bootstrap below.
    let genesis = genesis_transition(drive, &identity, &encryption)?;

    let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
    // Owner custody retained for mint-time escrow, like at create.
    engine.root = Some(root);
    engine.add_epoch_key(1, Zeroizing::new(epoch.control_key(&drive, 1)));
    // Resume an interrupted bootstrap: the custody record is durable but
    // the genesis commit was lost to a crash. The genesis is deterministic
    // and the supplied identity was checked against the recorded owner, so
    // completing it is safe and idempotent.
    if engine.log.known_state().is_none() {
        engine.commit_facts(&[Fact::Transition(genesis.clone())])?;
        engine.resync()?;
    }
    // Complete an interrupted self-capability install the same way (a
    // crash between the genesis commit and the capability commit would
    // otherwise leave a drive that can unlock mail but never seal
    // content): the escrow record covers exactly this epoch, and the
    // install is a no-op when the durable capability already exists.
    install_self_capability(&mut engine, &genesis, &epoch)?;
    // Restore every later epoch's control key from its escrow sidecar:
    // root custody alone re-derives the control plane even when the
    // keyring lost those epochs (T13 recovery). Missing sidecars are
    // the pre-escrow gap and fall back to keyring catch-up; corrupt
    // ones fail closed below.
    restore_escrowed_epochs(&mut engine)?;
    Ok(engine)
}

/// Install the local owner's epoch material as a durable self-capability,
/// so the keyring rebuilt from facts holds the content/manifest sealing
/// secrets for exactly the epochs the custody escrow covers. The mailbox
/// control key stays in `epoch_keys` (per-process, never durable). A
/// keyring that already holds the epoch skips the commit: replay-safe by
/// the same idempotence the capability facts themselves carry.
fn install_self_capability(
    engine: &mut Engine,
    genesis: &MembershipTransition,
    epoch: &EpochSecret,
) -> Result<(), EngineError> {
    if engine
        .store
        .rebuild(engine.device)?
        .keyring
        .secret(genesis.epoch)
        .is_some()
    {
        return Ok(());
    }
    let cap = Capability::new(
        engine.drive,
        engine.device,
        engine.encryption_secret.encryption_key(),
        genesis.transition_id(),
        genesis.epoch,
        vec![epoch.clone()],
    )?;
    let authorized =
        AuthorizedCapability::authorize(cap, engine.drive, &engine.log, &genesis.transition_id())
            .map_err(EngineError::Capability)?;
    engine.commit_facts(&[Fact::Capability(authorized)])?;
    Ok(())
}

/// Install the control key of every escrowed epoch secret (T13
/// recovery): root custody alone re-derives the control plane for
/// epochs whose keyring material was lost. Epoch 1 keeps its
/// historical keystore-escrow path in the caller; epochs 2+ read
/// their sidecars up to the known tip. Missing sidecars are the
/// pre-escrow gap (or a commit-then-escrow crash window) and skip to
/// keyring catch-up; a present record for the wrong drive, or one
/// that fails the tag, is corrupt custody and fails closed — a
/// guardian must never install a secret the root did not seal.
///
/// Conflict policy (fill-vacant, never replace): a sidecar whose
/// secret differs from the already-held epoch key fails the open
/// with `EscrowConflict` instead of swapping the key the durable
/// fact history runs on. Escrow restores vacant epochs; it never
/// outranks held material — the same rule the invitation resync
/// applies to provisional secrets.
pub(super) fn restore_escrowed_epochs(engine: &mut Engine) -> Result<(), EngineError> {
    if engine.root.is_none() {
        // Member engines and keystoreless opens hold no root and
        // escrow nothing.
        return Ok(());
    }
    let drive = engine.drive;
    let dir = engine.store.dir().to_path_buf();
    let tip = engine
        .log
        .known_state()
        .map(|known| known.epoch)
        .unwrap_or(0);
    for epoch in 2..=tip {
        let Some(record) = escrow::load_record(&dir, epoch)? else {
            continue;
        };
        if record.drive != drive || record.epoch != epoch {
            return Err(EngineError::MalformedKeystore);
        }
        // Borrow the root for one derivation at a time: the previous
        // shape cloned it across the whole loop. The clone scrubbed
        // itself on drop, but a borrow holds no second copy at all —
        // and the short borrow never crosses the `&mut` keyring
        // install below.
        let secret = {
            let Some(root) = engine.root.as_ref() else {
                // Unreachable: presence is checked above and nothing
                // in this loop replaces the root. Fail closed rather
                // than report success after a partial restore.
                return Err(EngineError::EscrowRootLost);
            };
            escrow::unwrap(&root.escrow_key(&drive, epoch), &record)?
        };
        let key = secret.control_key(&drive, epoch);
        match engine.epoch_keys.get(&epoch) {
            // Same secret already held (e.g. keyring-derived):
            // leave it. Restoration fills vacancies only.
            Some(held) if **held == key => {}
            // A validly sealed but different secret: corrupt or
            // transplanted custody. Fail the open rather than run
            // the durable history on a replaced key.
            Some(_) => return Err(EngineError::EscrowConflict(epoch)),
            None => {
                engine.add_epoch_key(epoch, Zeroizing::new(key));
            }
        }
    }
    Ok(())
}

/// The genesis membership transition (epochs.md): the owner admits itself
/// and sets itself as the sole owner, at epoch 1 with no `prev`. Signed by
/// the owner's identity.
pub(super) fn genesis_transition(
    drive: DriveId,
    identity: &DeviceIdentitySecret,
    encryption: &DeviceEncryptionSecret,
) -> Result<MembershipTransition, EngineError> {
    let owner = identity.device_id();
    let mut transition = MembershipTransition::new(
        1,
        None,
        Vec::new(),
        vec![
            Change::Admit(Admission {
                device: owner,
                encryption_key: encryption.encryption_key(),
            }),
            Change::SetOwners(vec![owner]),
        ],
        set_root(MEMBER_SET_CONTEXT, &[owner])?,
        set_root(OWNER_SET_CONTEXT, &[owner])?,
        set_root(READER_SET_CONTEXT, &[])?,
        owner,
    )?;
    sign_transition(&mut transition, &identity.secret_key(), &drive);
    Ok(transition)
}

/// The custody record: `version ‖ owner (32) ‖ len(root) ‖ len(device) ‖
/// len(escrow) ‖ root ‖ device ‖ escrow`, each length a `u16` LE. The
/// owner is the public `DeviceId` that owns the drive; it lets a resume
/// verify the supplied identity before completing an interrupted genesis.
pub(super) fn encode_custody(
    owner: &DeviceId,
    root: &WrappedSecret,
    device: &WrappedSecret,
    escrow_record: &escrow::EscrowRecord,
) -> Vec<u8> {
    let root = root.as_bytes();
    let device = device.as_bytes();
    let escrow = escrow_record.encode();
    let mut out = Vec::with_capacity(1 + 32 + 6 + root.len() + device.len() + escrow.len());
    out.push(KEYSTORE_VERSION);
    out.extend_from_slice(owner.as_bytes());
    out.extend_from_slice(&(root.len() as u16).to_le_bytes());
    out.extend_from_slice(&(device.len() as u16).to_le_bytes());
    out.extend_from_slice(&(escrow.len() as u16).to_le_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(device);
    out.extend_from_slice(&escrow);
    out
}

/// What a drive directory's custody record holds: the creator's
/// full root custody, or a joined member's device secret alone. The
/// version byte selects; anything else is malformed.
pub(super) enum Custody {
    Owner {
        owner: DeviceId,
        root: WrappedSecret,
        device: WrappedSecret,
        escrow: escrow::EscrowRecord,
    },
    Member {
        device: DeviceId,
        device_secret: WrappedSecret,
    },
}

pub(super) fn decode_custody(bytes: &[u8]) -> Result<Custody, EngineError> {
    if bytes.is_empty() {
        return Err(EngineError::MalformedKeystore);
    }
    match bytes[0] {
        KEYSTORE_VERSION => decode_owner_custody(bytes),
        MEMBER_KEYSTORE_VERSION => decode_member_custody(bytes),
        _ => Err(EngineError::MalformedKeystore),
    }
}

/// A member custody record: the joined device plus its
/// passphrase-wrapped encryption secret. Same length-prefixed shape
/// as the owner record, minus root and escrow.
pub(super) fn encode_member_custody(device: &DeviceId, wrapped: &WrappedSecret) -> Vec<u8> {
    let secret = wrapped.as_bytes();
    let mut out = Vec::with_capacity(1 + 32 + 2 + secret.len());
    out.push(MEMBER_KEYSTORE_VERSION);
    out.extend_from_slice(device.as_bytes());
    out.extend_from_slice(&(secret.len() as u16).to_le_bytes());
    out.extend_from_slice(secret);
    out
}

/// Persist a member custody record over any previous one. Join writes
/// this before accepting the invitation: the secret must be on disk
/// before any fact commits, or a crash between the two loses the only
/// copy. Re-running join reuses the staged secret, so overwriting
/// with the same bytes is the idempotent resume path.
pub(super) fn write_member_custody(
    dir: &Path,
    device: &DeviceId,
    wrapped: &WrappedSecret,
) -> Result<(), EngineError> {
    atomic_write_mode(
        dir,
        KEYSTORE_FILE,
        &encode_member_custody(device, wrapped),
        SECRET_FILE_MODE,
    )
    .map_err(EngineError::Io)
}

fn decode_owner_custody(bytes: &[u8]) -> Result<Custody, EngineError> {
    const HEADER: usize = 1 + 32 + 6;
    if bytes.len() < HEADER || bytes[0] != KEYSTORE_VERSION {
        return Err(EngineError::MalformedKeystore);
    }
    let owner = DeviceId::from_bytes(bytes[1..33].try_into().expect("bounds checked"));
    let len = |pos: usize| u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    let (root_len, device_len, escrow_len) = (len(33), len(35), len(37));
    let mut pos = HEADER;
    let mut take = |n: usize| -> Result<Vec<u8>, EngineError> {
        let end = pos.checked_add(n).ok_or(EngineError::MalformedKeystore)?;
        if end > bytes.len() {
            return Err(EngineError::MalformedKeystore);
        }
        let slice = bytes[pos..end].to_vec();
        pos = end;
        Ok(slice)
    };
    let root = WrappedSecret::from_bytes(take(root_len)?);
    let device = WrappedSecret::from_bytes(take(device_len)?);
    let escrow_record = escrow::EscrowRecord::decode(&take(escrow_len)?)?;
    if pos != bytes.len() {
        return Err(EngineError::MalformedKeystore);
    }
    Ok(Custody::Owner {
        owner,
        root,
        device,
        escrow: escrow_record,
    })
}

fn decode_member_custody(bytes: &[u8]) -> Result<Custody, EngineError> {
    const HEADER: usize = 1 + 32 + 2;
    if bytes.len() < HEADER || bytes[0] != MEMBER_KEYSTORE_VERSION {
        return Err(EngineError::MalformedKeystore);
    }
    let device = DeviceId::from_bytes(bytes[1..33].try_into().expect("bounds checked"));
    let secret_len = u16::from_le_bytes([bytes[33], bytes[34]]) as usize;
    let end = HEADER
        .checked_add(secret_len)
        .ok_or(EngineError::MalformedKeystore)?;
    if end != bytes.len() {
        return Err(EngineError::MalformedKeystore);
    }
    let device_secret = WrappedSecret::from_bytes(bytes[HEADER..end].to_vec());
    Ok(Custody::Member {
        device,
        device_secret,
    })
}

/// Undo a failed create. The custody record always goes; the store
/// artifacts go when this call created the store, so a pre-existing
/// directory keeps unrelated files.
fn rollback(dir: &Path, dir_created: bool) {
    let _ = std::fs::remove_file(dir.join(KEYSTORE_FILE));
    if dir_created {
        let _ = std::fs::remove_dir_all(dir);
        return;
    }
    for name in ["DRIVE", "store-key.wrap", "CURRENT", "LOCK"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir_all(dir.join("commits"));
}

pub(super) fn read_custody(dir: &Path) -> Result<Custody, EngineError> {
    decode_custody(&std::fs::read(dir.join(KEYSTORE_FILE))?)
}

/// The custody record if one is bound to the directory: a missing
/// file is a fresh directory, not an error. Used where the caller
/// guards before writing (join), never where a record is required
/// (open).
pub(super) fn read_custody_opt(dir: &Path) -> Result<Option<Custody>, EngineError> {
    match std::fs::read(dir.join(KEYSTORE_FILE)) {
        Ok(bytes) => decode_custody(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(EngineError::Io(error)),
    }
}

pub(super) fn read_drive(dir: &Path) -> Result<DriveId, EngineError> {
    let bytes = std::fs::read(dir.join("DRIVE"))?;
    let id: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::MalformedDrive)?;
    Ok(DriveId::from_bytes(id))
}
