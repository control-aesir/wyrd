//! Local drive bootstrap: create a new drive from scratch and reopen it.
//!
//! The rest of the runtime assumes a drive already exists: `Engine::open`
//! needs a durable store bound to a drive id, and the write path needs a
//! canonical membership state. In tests both came from fixtures. This is
//! the production producer, and it persists the custody material the
//! trust model assigns to the local keystore so the drive survives the
//! creating process.
//!
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
//! A single-device drive only; admitting more devices (bootstrap
//! invitations, capabilities) and root recovery are later slices. The
//! drive starts headless; the first snapshot comes from
//! [`Engine::author_snapshot`](super::engine::Engine::author_snapshot).

use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use wyrd_format::membership::{
    set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT, READER_SET_CONTEXT,
};
use wyrd_format::{Change, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition};

use super::engine::{Engine, EngineError};
use crate::control::bootstrap::{open_bootstrap, SealedBootstrap};
use crate::durable::{
    atomic_write, fsync_dir, AuthorizedCapability, DurableError, DurableStore, Fact,
};
use crate::keys::capability::{Capability, DriveKeyring, WrappedCapability};
use crate::keys::keystore::{
    unwrap_device_secret, unwrap_root, wrap_device_secret, wrap_root, WrappedSecret,
};
use crate::keys::{
    escrow, random_bytes, DeviceEncryptionSecret, DeviceIdentitySecret, DriveRootKey, EpochSecret,
};
use crate::membership::{sign_transition, Authorizable, MembershipLog};

/// The custody record file inside a drive directory.
const KEYSTORE_FILE: &str = "keystore";

/// The only custody-record version.
const KEYSTORE_VERSION: u8 = 0x02;

/// The member custody-record version: a joined device's store carries
/// its own encryption secret and nothing else — no root, no escrow.
/// Members never hold either; epoch keys re-derive from the pending
/// invitation on every resync.
const MEMBER_KEYSTORE_VERSION: u8 = 0x03;

/// Create a new single-device drive. `identity` is the owner's Nostr
/// identity (the signer's key, T6); everything else is generated and
/// persisted under `passphrase`. Fails if the directory already holds a
/// drive, so creation never clobbers one. On any failure the call rolls
/// back what it created.
pub(super) fn create(
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
    std::fs::create_dir_all(&dir)?;

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
        atomic_write(&dir, KEYSTORE_FILE, &custody)?;
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
pub(super) fn open_keystore(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<Engine, EngineError> {
    let drive = read_drive(&dir)?;
    match read_custody(&dir)? {
        Custody::Owner {
            owner,
            root: root_wrapped,
            device: device_wrapped,
            escrow: escrow_record,
        } => open_owner_keystore(
            dir,
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
            let mut engine = Engine::open(dir, drive, device, passphrase, identity, encryption)?;
            engine.resync()?;
            Ok(engine)
        }
    }
}

/// The owner half of [`open_keystore`]: root and epoch-1 escrow unwrap,
/// the deterministic genesis completes an interrupted bootstrap, and
/// the self capability installs exactly the escrowed epoch.
#[allow(clippy::too_many_arguments)]
fn open_owner_keystore(
    dir: PathBuf,
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

    let mut engine = Engine::open(dir, drive, device, passphrase, identity, encryption)?;
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
    Ok(engine)
}

/// Join a drive as an invited device: open the owner's sealed
/// invitation with the invitee's encryption secret, bind a fresh store
/// directory to the invitation's drive, and commit its genesis.
/// Idempotent like the interrupted-create resume: a redelivered
/// invitation resumes where the first call stopped.
///
/// Trust reasoning, stated exactly because this path installs key
/// material before the chain authorizes it:
///
/// - The invitation is owner-signed and ECDH-sealed to the invitee
///   (`open_bootstrap` verifies both), so the epoch secrets inside
///   carry the inviter's authority for control-plane decryption keys.
///   Every message opened with those keys is still independently
///   verified (signatures, chain, membership), so a control key alone
///   grants no content and no authorship.
/// - No capability fact commits here. The invitation capability
///   authorizes against the admission state, which the newcomer hasn't
///   observed yet; committing it now would launder an unverified grant
///   into the durable keyring. Instead the wrapped bytes commit as a
///   [`Fact::BootstrapPending`] record and every resync re-derives the
///   control keys from it — restart-safe by construction. The record is
///   never removed (append-only); it stays inert once authorized keys
///   arrive because installation is gated: resync verifies every
///   bootstrap secret against the authorized keyring and the held keys
///   before installing anything, so provisional material can neither
///   outrank nor silently replace authorized keys, and a disagreeing
///   blob fails the resync closed.
pub(super) fn accept_invitation(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
    encryption: DeviceEncryptionSecret,
    sealed: &SealedBootstrap,
) -> Result<Engine, EngineError> {
    let verified = verify_invitation(&identity, &encryption, sealed)?;

    let store = DurableStore::open(dir.clone(), verified.drive, passphrase)?;
    if read_drive(&dir)? != verified.drive {
        return Err(EngineError::DriveExists);
    }
    accept_with_store(
        store,
        verified.drive,
        verified.device,
        identity,
        encryption,
        verified.genesis,
        verified.pending_capability,
    )
}

/// The verified invitation material: the invitee device, the drive,
/// the valid authoritative genesis, and the pending capability
/// bytes. Shared by accept and join so both enforce the identical
/// checks — signature, recipient, genesis validity, capability
/// binding — before anything touches disk.
struct VerifiedInvitation {
    device: DeviceId,
    drive: DriveId,
    genesis: MembershipTransition,
    pending_capability: Vec<u8>,
}

fn verify_invitation(
    identity: &DeviceIdentitySecret,
    encryption: &DeviceEncryptionSecret,
    sealed: &SealedBootstrap,
) -> Result<VerifiedInvitation, EngineError> {
    let device = identity.device_id();
    let invitation = open_bootstrap(encryption, sealed)?;
    if invitation.invitee != device {
        return Err(EngineError::InvitationMismatch);
    }
    let genesis = MembershipTransition::from_canonical_bytes(&invitation.genesis)
        .map_err(|_| EngineError::BadGenesis)?;
    if genesis.epoch != 1 || genesis.prev.is_some() {
        return Err(EngineError::BadGenesis);
    }
    // The envelope signature covers arbitrary bytes: a validly signed
    // invitation can still carry an invalid transition. Observe the
    // candidate in a temporary log and require a valid authoritative
    // genesis — signature, drive binding, roots, owner/member state —
    // before committing anything. A buggy or malicious inviter must
    // not produce an engine with no canonical state.
    let mut candidate = MembershipLog::new(invitation.drive);
    let genesis_id = candidate.observe(genesis.clone());
    if !matches!(
        candidate.authoritative(&genesis_id),
        Some(Authorizable::Valid(..))
    ) {
        return Err(EngineError::BadGenesis);
    }
    // Fail before touching disk when the invitation's capability names
    // another device: the seal is addressed to us but the grant inside
    // is not ours. The unwrap also proves the encryption secret opens
    // the pending record every later open will re-derive from.
    let capability = WrappedCapability::from_bytes(invitation.capability.clone())
        .unwrap(encryption)
        .map_err(EngineError::Crypto)?;
    if capability.device != device {
        return Err(EngineError::InvitationMismatch);
    }
    // The wrap is ECDH-bound to our secret, but the grant names its
    // own drive and registration: refuse a structurally valid
    // capability for another drive before its secrets become our
    // control keys. The encryption-key half is pinned independently by
    // both the seal's header check and the wrap's AAD — the explicit
    // comparison backstops future crypto refactors. The transition
    // binding is deliberately unchecked here: the grant may bind the
    // admission transition rather than the genesis, and it authorizes
    // through intake once the catch-up set lands, never at accept.
    if capability.drive != invitation.drive
        || capability.encryption_key != invitation.encryption_key
    {
        return Err(EngineError::InvitationMismatch);
    }
    Ok(VerifiedInvitation {
        device,
        drive: invitation.drive,
        genesis,
        pending_capability: invitation.capability,
    })
}

/// The store-held half of [`accept_invitation`]: commit the invitation
/// genesis plus the pending capability record, then resync. Split out
/// so [`join`] can hold the store lock across the custody guard, the
/// custody write, and the accept — concurrent joiners serialize on
/// the lock instead of racing the keystore write past each other.
fn accept_with_store(
    store: DurableStore,
    drive: DriveId,
    device: DeviceId,
    identity: DeviceIdentitySecret,
    encryption: DeviceEncryptionSecret,
    genesis: MembershipTransition,
    pending_capability: Vec<u8>,
) -> Result<Engine, EngineError> {
    let mut engine = Engine::open_with_store(store, drive, device, identity, encryption)?;
    if engine.log.known_state().is_none() {
        engine.log.observe(genesis.clone());
        engine.commit_facts(&[
            Fact::Transition(genesis),
            Fact::BootstrapPending(pending_capability),
        ])?;
    }
    // The commit above carries the pending record, so this resync
    // installs the invitation's control keys from durable state — the
    // same path every later open takes.
    engine.resync()?;
    Ok(engine)
}

/// Re-derive epoch control keys from one pending-invitation blob: the
/// wrapped capability's secrets cover `1..=N` contiguously by
/// construction, so every secret installs its epoch's key and the
/// catch-up set opens regardless of which epoch sealed each message.
/// Provisional and gated, never authoritative: every secret is verified
/// against the authorized keyring and the held keys before anything
/// installs, so a stale or forged blob fails the resync closed instead
/// of swapping keys behind sealed traffic. Deterministic and
/// idempotent: reopening re-installs identical keys.
pub(super) fn install_invitation_keys(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    wrapped: Vec<u8>,
) -> Result<(), EngineError> {
    let drive = engine.drive;
    let capability = WrappedCapability::from_bytes(wrapped)
        .unwrap(&engine.encryption_secret)
        .map_err(EngineError::Crypto)?;
    // Verify everything before installing anything: a conflict leaves
    // the held keys untouched and fails closed.
    let mut derived = Vec::with_capacity(capability.secrets.len());
    for (index, secret) in capability.secrets.iter().enumerate() {
        let epoch = index as u64 + 1;
        derived.push((epoch, secret.control_key(&drive, epoch)));
    }
    for (epoch, key) in &derived {
        if let Some(known) = keyring.secret(*epoch) {
            if known.control_key(&drive, *epoch) != *key {
                return Err(EngineError::BootstrapKeyConflict(*epoch));
            }
        }
        if let Some(held) = engine.epoch_keys.get(epoch) {
            if held[..] != key[..] {
                return Err(EngineError::BootstrapKeyConflict(*epoch));
            }
        }
    }
    for (epoch, key) in derived {
        // `add_epoch_key` overwrites, but every held key above was just
        // proven equal, so this only fills vacant epochs.
        engine.add_epoch_key(epoch, Zeroizing::new(key));
    }
    Ok(())
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

/// The genesis membership transition (epochs.md): the owner admits itself
/// and sets itself as the sole owner, at epoch 1 with no `prev`. Signed by
/// the owner's identity.
fn genesis_transition(
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
fn encode_custody(
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
enum Custody {
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

fn decode_custody(bytes: &[u8]) -> Result<Custody, EngineError> {
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
fn encode_member_custody(device: &DeviceId, wrapped: &WrappedSecret) -> Vec<u8> {
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
    atomic_write(dir, KEYSTORE_FILE, &encode_member_custody(device, wrapped))
        .map_err(EngineError::Io)
}

/// A newcomer's pairing material: the device id plus the encryption
/// key the owner admits. No secrets — safe to ferry out-of-band to
/// the owner alongside the invite request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingRequest {
    pub device: DeviceId,
    pub encryption_key: DeviceEncryptionKey,
}

/// The staged pairing secret: generated once per newcomer directory
/// and wrapped under the passphrase. Created atomically (`create_new`
/// claims the file; the loser of a concurrent race reuses the
/// winner's wrap), so two pairing-requests can never strand an
/// admission under a key this device no longer holds.
const PAIRING_FILE: &str = "pairing.secret";

/// Stage this device's pairing secret (or reuse the staged one) and
/// return the public pairing material. Re-running returns the same
/// key: the owner may already have admitted it, so regenerating
/// would strand the admission.
pub(super) fn pairing_request(
    dir: &Path,
    passphrase: &str,
    identity: &DeviceIdentitySecret,
) -> Result<PairingRequest, EngineError> {
    std::fs::create_dir_all(dir)?;
    let device = identity.device_id();
    let path = dir.join(PAIRING_FILE);
    let secret = match std::fs::read(&path) {
        Ok(staged) => unwrap_pairing_secret(&staged, passphrase)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let fresh = DeviceEncryptionSecret::generate()?;
            let wrapped = wrap_device_secret(fresh.as_bytes(), passphrase)?;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    file.write_all(wrapped.as_bytes())?;
                    file.sync_all()?;
                    drop(file);
                    fsync_dir(dir)?;
                    fresh
                }
                // Lost the race: the winner's wrap is authoritative.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    unwrap_pairing_secret(&std::fs::read(&path)?, passphrase)?
                }
                Err(error) => return Err(EngineError::Io(error)),
            }
        }
        Err(error) => return Err(EngineError::Io(error)),
    };
    Ok(PairingRequest {
        device,
        encryption_key: secret.encryption_key(),
    })
}

fn unwrap_pairing_secret(
    staged: &[u8],
    passphrase: &str,
) -> Result<DeviceEncryptionSecret, EngineError> {
    DeviceEncryptionSecret::from_bytes(unwrap_device_secret(
        &WrappedSecret::from_bytes(staged.to_vec()),
        passphrase,
    )?)
    .map_err(EngineError::Crypto)
}

/// Join from the staged pairing secret plus the owner's sealed
/// invitation. The staged secret must open the invitation before
/// anything touches disk; the store lock is then held across the
/// custody guard, the custody write, and the accept, so concurrent
/// joiners serialize instead of racing the keystore past each other.
/// Member custody persists before the accept commits, so a crash
/// between the two resumes with the secret on disk (the accept
/// itself is idempotent). Custody is never clobbered: an owner
/// record refuses outright, and a member record for another device
/// refuses rather than stranding it.
pub(super) fn join(
    dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
    sealed: &SealedBootstrap,
) -> Result<Engine, EngineError> {
    let staged = read_pairing_secret(&dir, passphrase)?;
    let verified = verify_invitation(&identity, &staged, sealed)?;
    let device = verified.device;
    // The store open binds the directory to the invitation's drive
    // and takes the lock every later step holds; a directory bound
    // to another drive refuses here, before any custody is touched.
    let store = match DurableStore::open(dir.clone(), verified.drive, passphrase) {
        Err(DurableError::DriveMismatch) => return Err(EngineError::DriveExists),
        store => store?,
    };
    match read_custody_opt(&dir)? {
        Some(Custody::Owner { .. }) => return Err(EngineError::OwnerCustodyExists),
        Some(Custody::Member {
            device: recorded, ..
        }) if recorded != device => return Err(EngineError::DeviceMismatch),
        _ => {}
    }
    write_member_custody(
        &dir,
        &device,
        &wrap_device_secret(staged.as_bytes(), passphrase)?,
    )?;
    accept_with_store(
        store,
        verified.drive,
        device,
        identity,
        staged,
        verified.genesis,
        verified.pending_capability,
    )
}

/// The staged pairing secret, or a directed error when pairing never
/// ran: joining without staging would mint a key the owner never
/// admitted.
fn read_pairing_secret(
    dir: &Path,
    passphrase: &str,
) -> Result<DeviceEncryptionSecret, EngineError> {
    match std::fs::read(dir.join(PAIRING_FILE)) {
        Ok(staged) => unwrap_pairing_secret(&staged, passphrase),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(EngineError::MissingPairingSecret)
        }
        Err(error) => Err(EngineError::Io(error)),
    }
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

fn read_custody(dir: &Path) -> Result<Custody, EngineError> {
    decode_custody(&std::fs::read(dir.join(KEYSTORE_FILE))?)
}

/// The custody record if one is bound to the directory: a missing
/// file is a fresh directory, not an error. Used where the caller
/// guards before writing (join), never where a record is required
/// (open).
fn read_custody_opt(dir: &Path) -> Result<Option<Custody>, EngineError> {
    match std::fs::read(dir.join(KEYSTORE_FILE)) {
        Ok(bytes) => decode_custody(&bytes).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(EngineError::Io(error)),
    }
}

fn read_drive(dir: &Path) -> Result<DriveId, EngineError> {
    let bytes = std::fs::read(dir.join("DRIVE"))?;
    let id: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::MalformedDrive)?;
    Ok(DriveId::from_bytes(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::bootstrap::seal_bootstrap;
    use crate::control::{seal, KeyRotation, Message};
    use crate::keys::capability::Capability;
    use crate::runtime::test_util::{MemoryMailbox, MemoryRelay, TestDir};
    use crate::transport::mailbox::seal_for_recipient;
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
        let mut owner =
            create(owner_dir.path.clone(), "test-pass", owner_identity.clone()).unwrap();
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
}
