//! Durable local state: an append-only commit log with an atomic commit
//! marker (durable-state issue).
//!
//! Layout under one drive directory:
//!
//! ```text
//! drive/
//!   DRIVE              32-byte drive id, written once at creation
//!   store-key.wrap     store key sealed under the passphrase
//!   CURRENT            8-byte LE last durable commit sequence
//!   commits/
//!     0000000000000001.commit
//!     ...
//! ```
//!
//! Commit protocol (single writer — no locking in v1):
//!
//! 1. Serialize the commit (canonical records) to a temp file.
//! 2. `fsync` the temp file.
//! 3. Rename it to `<seq>.commit`.
//! 4. `fsync` the `commits/` directory: the rename must be durable
//!    before CURRENT may advance past it.
//! 5. Advance CURRENT via temp + `fsync` + rename + directory `fsync`.
//!
//! The critical invariant: **a commit is visible iff its sequence is
//! `<=` the durable CURRENT.** Recovery replays commits `1..=CURRENT`
//! and ignores orphaned `.tmp` files, unparsable commit files, and
//! unknown record tags; a missing commit file at or below CURRENT is
//! store damage and fails the load. Directory `fsync`s are part of the
//! contract: renames are filesystem metadata and must reach stable
//! storage too.
//!
//! Facts, not state: commits carry canonical records (transitions,
//! sealed capabilities, announcements, manifests, residency facts).
//! Loading replays them into a [`MembershipLog`], a [`DriveKeyring`],
//! and a [`RuntimeState`]; the caller runs `reconcile()` for the fetch
//! plan. Derived indexes are rebuilt, never persisted, so two
//! representations of the same DAG can never disagree.
//!
//! Capabilities cross the durability boundary only as
//! [`AuthorizedCapability`]: validated against membership state at
//! commit time, sealed under the store key at rest, re-validated on
//! rebuild. The persistence layer can never launder an unauthorized
//! capability into the keyring.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use wyrd_format::{
    ContentId, DeviceEncryptionKey, DeviceId, DriveId, Manifest, ManifestError, MembershipError,
    MembershipTransition, ObjectKind, StorageId, TransitionId,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::control::message::{ControlKind, Message};
use crate::control::{ControlError, ControlMessageId, SnapshotAnnouncement};
use crate::keys::capability::{
    plaintext_bytes, Capability, CapabilityError, DriveKeyring, InstallError,
};
use crate::keys::epoch::EpochSecret;
use crate::keys::keystore::{kdf_key, KeystoreError, KDF_SALT_LEN};
use crate::keys::{aead, random_bytes, CryptoError};
use crate::membership::{MembershipLog, MembershipState};
use crate::runtime::{ManifestRecord, MaterializationState, RuntimeError, RuntimeState};

// --- record tags -----------------------------------------------------------

const COMMIT_VERSION: u8 = 0x00;
const TAG_TRANSITION: u8 = 0x01;
const TAG_CAPABILITY: u8 = 0x02;
const TAG_ANNOUNCEMENT: u8 = 0x03;
const TAG_MANIFEST: u8 = 0x04;
const TAG_LOCAL_OBJECT: u8 = 0x05;
const TAG_MATERIALIZATION: u8 = 0x06;
const TAG_CONTROL_MESSAGE: u8 = 0x07;

/// AAD domain for the store key envelope (keystore-shaped, own domain so
/// a wrapped store key can never open as a root or device secret).
const STORE_KEY_AAD: &[u8] = b"wyrd store key v1";
/// AAD domain for sealed capabilities at rest. The store key is fresh
/// random per store, so no cross-context confusion is possible; the
/// distinct domain states the intent anyway.
const CAPABILITY_STORE_AAD: &[u8] = b"wyrd capability store v1";

// --- errors ----------------------------------------------------------------

/// Durable-store failures. I/O errors propagate; everything else names
/// the damaged or mismatched durable fact.
#[derive(Debug, Error)]
pub enum DurableError {
    #[error("durable I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("CURRENT is present but not an 8-byte sequence")]
    CorruptCurrent,
    #[error("store holds another drive")]
    DriveMismatch,
    #[error("store key failed: {0}")]
    StoreKey(#[from] KeystoreError),
    #[error("crypto failed: {0}")]
    Crypto(#[from] CryptoError),
    #[error("capability failed: {0}")]
    Capability(#[from] CapabilityError),
    #[error("manifest failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("membership transition failed: {0}")]
    Membership(#[from] MembershipError),
    #[error("control decoding failed: {0}")]
    Control(#[from] ControlError),
    #[error("runtime rebuild failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("keyring install failed: {0}")]
    Install(#[from] InstallError),
    #[error("commit {0} is missing at or below CURRENT")]
    MissingCommit(u64),
    #[error("capability for {0:?} no longer validates on rebuild")]
    CapabilityChanged(DeviceId),
    #[error("capability references a transition with no derived state")]
    CapabilityTransitionUnknown,
}

// --- facts -----------------------------------------------------------------

/// A capability that passed membership validation and may be durably
/// recorded. Constructible only through [`AuthorizedCapability::authorize`],
/// so the commit path cannot persist a capability that was never checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedCapability {
    cap: Capability,
}

impl AuthorizedCapability {
    /// Validate the capability against the authoritative membership state
    /// (member with the registered encryption key) and wrap it for
    /// durability.
    pub fn authorize(cap: Capability, state: &MembershipState) -> Result<Self, CapabilityError> {
        cap.validate_against(state)?;
        Ok(AuthorizedCapability { cap })
    }

    /// The validated capability.
    pub fn capability(&self) -> &Capability {
        &self.cap
    }
}

/// One durable mutation. All variants carry canonical records; the commit
/// envelope frames them with type tags and lengths.
#[derive(Debug, Clone)]
pub enum Fact {
    /// An observed membership transition (canonical bytes on the wire).
    Transition(MembershipTransition),
    /// A validated capability (sealed under the store key at rest).
    Capability(AuthorizedCapability),
    /// A snapshot announcement.
    Announcement(SnapshotAnnouncement),
    /// A manifest record (identity-checked at commit).
    Manifest(ManifestRecord),
    /// A locally present object.
    LocalObject(ContentId),
    /// A residency policy entry.
    Materialization(ContentId, MaterializationState),
    /// A seen control-message id (dedupe set).
    ControlMessage(ControlMessageId),
}

/// The replayed facts of commits `1..=CURRENT`, in commit order.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoadedFacts {
    pub transitions: Vec<MembershipTransition>,
    pub capabilities: Vec<Capability>,
    pub announcements: Vec<SnapshotAnnouncement>,
    pub manifests: Vec<ManifestRecord>,
    pub local_objects: Vec<ContentId>,
    pub materialization: Vec<(ContentId, MaterializationState)>,
    pub seen: Vec<ControlMessageId>,
}

/// The reconstructed live state: facts replayed through the same
/// machines that accepted them. The caller runs `runtime.reconcile()`
/// for the fetch plan.
#[derive(Debug)]
pub struct Rebuilt {
    pub log: MembershipLog,
    pub keyring: DriveKeyring,
    pub runtime: RuntimeState,
}

// --- crash stages ----------------------------------------------------------

/// Commit-protocol boundaries for crash-injection tests: `commit_until`
/// executes the protocol through the named stage and then stops,
/// simulating power loss. Reload must yield the previous or the fully
/// committed state — never a hybrid.
/// CrashStage variants other than `Complete` are constructed only by
/// crash-injection tests; the enum lives outside `cfg(test)` so the
/// commit protocol has a single entry point.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrashStage {
    AfterWriteTemp,
    AfterFsyncTemp,
    AfterRenameCommit,
    AfterFsyncCommitDir,
    AfterWriteCurrentTemp,
    AfterFsyncCurrentTemp,
    AfterRenameCurrent,
    Complete,
}

// --- the store ---------------------------------------------------------------

/// A random 256-bit store key, sealing capability records at rest. Held
/// in a zeroizing wrapper; itself wrapped under the passphrase on disk.
#[derive(ZeroizeOnDrop)]
struct StoreKey(Zeroizing<[u8; 32]>);

/// The durable commit log for one drive. Single writer. No `Debug`: the
/// store key must never be printable.
pub struct DurableStore {
    dir: PathBuf,
    drive: DriveId,
    current: u64,
    store_key: StoreKey,
}

fn commit_name(seq: u64) -> String {
    format!("{seq:016x}.commit")
}

fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Durably create-or-replace one file: temp + `fsync` + rename +
/// directory `fsync`. Fixed `.tmp` sibling; stale temps are overwritten,
/// never read.
fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(name))?;
    fsync_dir(dir)
}

impl DurableStore {
    fn commits_dir(&self) -> PathBuf {
        self.dir.join("commits")
    }

    /// Open (or create) the store: verify the drive id, unwrap or mint
    /// the store key, read CURRENT. Missing CURRENT means a fresh store.
    pub fn open(dir: PathBuf, drive: DriveId, passphrase: &str) -> Result<Self, DurableError> {
        let commits = dir.join("commits");
        fs::create_dir_all(&commits)?;
        // Drive identity, written once: a store directory never changes drives.
        let drive_path = dir.join("DRIVE");
        match fs::read(&drive_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                atomic_write(&dir, "DRIVE", drive.as_bytes())?;
            }
            Ok(bytes) => {
                if bytes.len() != 32 || bytes != drive.as_bytes() {
                    return Err(DurableError::DriveMismatch);
                }
            }
            Err(e) => return Err(DurableError::Io(e)),
        }
        let store_key = Self::load_or_mint_store_key(&dir, passphrase)?;
        let current = Self::read_current(&dir)?;
        Ok(DurableStore {
            dir,
            drive,
            current,
            store_key,
        })
    }

    /// The last durable commit sequence.
    pub fn current(&self) -> u64 {
        self.current
    }

    fn load_or_mint_store_key(dir: &Path, passphrase: &str) -> Result<StoreKey, DurableError> {
        let path = dir.join("store-key.wrap");
        match fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut raw = Zeroizing::new([0u8; 32]);
                random_bytes(raw.as_mut())?;
                let mut salt = [0u8; KDF_SALT_LEN];
                random_bytes(&mut salt)?;
                let key = kdf_key(passphrase, &salt)?;
                let mut nonce = [0u8; 24];
                random_bytes(&mut nonce)?;
                let ct = aead::seal(key.as_slice(), &nonce, raw.as_slice(), STORE_KEY_AAD)?;
                let mut bytes = Vec::with_capacity(KDF_SALT_LEN + 24 + ct.len());
                bytes.extend_from_slice(&salt);
                bytes.extend_from_slice(&nonce);
                bytes.extend_from_slice(&ct);
                atomic_write(dir, "store-key.wrap", &bytes)?;
                Ok(StoreKey(raw))
            }
            Ok(bytes) => {
                if bytes.len() != KDF_SALT_LEN + 24 + 48 {
                    return Err(DurableError::StoreKey(KeystoreError::Malformed));
                }
                let salt = &bytes[..KDF_SALT_LEN];
                let nonce: &[u8; 24] = bytes[KDF_SALT_LEN..KDF_SALT_LEN + 24]
                    .try_into()
                    .map_err(|_| KeystoreError::Malformed)
                    .map_err(DurableError::StoreKey)?;
                let key = kdf_key(passphrase, salt)?;
                let pt = aead::open(
                    key.as_slice(),
                    nonce,
                    &bytes[KDF_SALT_LEN + 24..],
                    STORE_KEY_AAD,
                )
                .map_err(|_| KeystoreError::WrongPassphrase)
                .map_err(DurableError::StoreKey)?;
                let raw: [u8; 32] = pt
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeystoreError::Malformed)
                    .map_err(DurableError::StoreKey)?;
                Ok(StoreKey(Zeroizing::new(raw)))
            }
            Err(e) => Err(DurableError::Io(e)),
        }
    }

    fn read_current(dir: &Path) -> Result<u64, DurableError> {
        match fs::read(dir.join("CURRENT")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Ok(bytes) => {
                if bytes.len() != 8 {
                    return Err(DurableError::CorruptCurrent);
                }
                Ok(u64::from_le_bytes(
                    bytes.try_into().expect("length checked"),
                ))
            }
            Err(e) => Err(DurableError::Io(e)),
        }
    }

    /// The AAD for sealed capabilities: domain plus drive. Device and
    /// epoch live inside the sealed plaintext and are cross-checked on
    /// open (exact length, epoch/count agreement, `Capability::new`
    /// shape, rebuild re-validation); the fresh random nonce per record
    /// already separates records under the store key.
    fn capability_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(CAPABILITY_STORE_AAD.len() + 32);
        aad.extend_from_slice(CAPABILITY_STORE_AAD);
        aad.extend_from_slice(self.drive.as_bytes());
        aad
    }

    /// Encode one fact to its (tag, record) pair, running the commit-time
    /// checks: manifest identity is derived (fail the commit, store
    /// untouched), capabilities arrive pre-authorized by type.
    fn encode_fact(&self, fact: &Fact) -> Result<(u8, Vec<u8>), DurableError> {
        match fact {
            Fact::Transition(t) => Ok((TAG_TRANSITION, t.canonical_bytes())),
            Fact::Capability(authorized) => {
                let cap = authorized.capability();
                let pt = plaintext_bytes(cap);
                let mut nonce = [0u8; 24];
                random_bytes(&mut nonce)?;
                let aad = self.capability_aad();
                let ct = aead::seal(self.store_key.0.as_slice(), &nonce, pt.as_slice(), &aad)?;
                let mut record = Vec::with_capacity(24 + ct.len());
                record.extend_from_slice(&nonce);
                record.extend_from_slice(&ct);
                Ok((TAG_CAPABILITY, record))
            }
            Fact::Announcement(a) => {
                let bytes = Message::SnapshotAnnouncement(a.clone()).encode_payload();
                Ok((TAG_ANNOUNCEMENT, bytes))
            }
            Fact::Manifest(record) => {
                let derived =
                    ContentId::derive(ObjectKind::Manifest, &record.manifest.canonical_bytes());
                if record.manifest_id != derived {
                    return Err(DurableError::Runtime(
                        RuntimeError::ManifestIdentityMismatch {
                            manifest: record.manifest_id,
                            derived,
                        },
                    ));
                }
                let mut bytes = Vec::new();
                bytes.extend_from_slice(record.manifest_id.as_bytes());
                bytes.push(u8::from(record.is_root));
                bytes.extend_from_slice(&(record.storage_ids.len() as u32).to_le_bytes());
                for id in &record.storage_ids {
                    bytes.extend_from_slice(id.as_bytes());
                }
                bytes.extend_from_slice(&record.manifest.canonical_bytes());
                Ok((TAG_MANIFEST, bytes))
            }
            Fact::LocalObject(id) => Ok((TAG_LOCAL_OBJECT, id.as_bytes().to_vec())),
            Fact::Materialization(id, state) => {
                let byte = match state {
                    MaterializationState::RemoteOnly => 0,
                    MaterializationState::Cached => 1,
                    MaterializationState::Pinned => 2,
                };
                let mut bytes = Vec::with_capacity(33);
                bytes.extend_from_slice(id.as_bytes());
                bytes.push(byte);
                Ok((TAG_MATERIALIZATION, bytes))
            }
            Fact::ControlMessage(id) => Ok((TAG_CONTROL_MESSAGE, id.as_bytes().to_vec())),
        }
    }

    /// Durably commit facts as the next sequence. Committing zero facts
    /// is a no-op returning the current sequence.
    pub fn commit(&mut self, facts: &[Fact]) -> Result<u64, DurableError> {
        self.commit_until(facts, CrashStage::Complete)
    }

    /// The commit protocol, stopping after the named stage to simulate
    /// power loss (tests only pass non-`Complete` stages). Production
    /// always runs to `Complete`.
    pub(crate) fn commit_until(
        &mut self,
        facts: &[Fact],
        stop: CrashStage,
    ) -> Result<u64, DurableError> {
        if facts.is_empty() {
            return Ok(self.current);
        }
        // Refresh against disk: a crashed predecessor may have advanced
        // CURRENT further than this handle saw.
        self.current = Self::read_current(&self.dir)?.max(self.current);
        let mut records = Vec::with_capacity(facts.len());
        for fact in facts {
            records.push(self.encode_fact(fact)?);
        }
        let seq = self.current + 1;
        let bytes = encode_commit(seq, &records);
        let name = commit_name(seq);
        let commits = self.commits_dir();

        let tmp = commits.join(format!("{name}.tmp"));
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
        }
        if stop == CrashStage::AfterWriteTemp {
            return Ok(self.current);
        }
        File::open(&tmp)?.sync_all()?;
        if stop == CrashStage::AfterFsyncTemp {
            return Ok(self.current);
        }
        fs::rename(&tmp, commits.join(&name))?;
        if stop == CrashStage::AfterRenameCommit {
            return Ok(self.current);
        }
        fsync_dir(&commits)?;
        if stop == CrashStage::AfterFsyncCommitDir {
            return Ok(self.current);
        }
        let current_bytes = seq.to_le_bytes();
        let current_tmp = self.dir.join("CURRENT.tmp");
        {
            let mut f = File::create(&current_tmp)?;
            f.write_all(&current_bytes)?;
        }
        if stop == CrashStage::AfterWriteCurrentTemp {
            return Ok(self.current);
        }
        File::open(&current_tmp)?.sync_all()?;
        if stop == CrashStage::AfterFsyncCurrentTemp {
            return Ok(self.current);
        }
        fs::rename(&current_tmp, self.dir.join("CURRENT"))?;
        self.current = seq;
        if stop == CrashStage::AfterRenameCurrent {
            return Ok(seq);
        }
        fsync_dir(&self.dir)?;
        Ok(seq)
    }

    /// Replay commits `1..=CURRENT` into facts, in commit order. Orphaned
    /// `.tmp` files, unparsable commit files, and unknown record tags
    /// are ignored; a missing commit at or below CURRENT fails the load.
    pub fn load(&self) -> Result<LoadedFacts, DurableError> {
        let current = Self::read_current(&self.dir)?;
        let mut facts = LoadedFacts::default();
        for seq in 1..=current {
            let path = self.commits_dir().join(commit_name(seq));
            let bytes = match fs::read(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(DurableError::MissingCommit(seq));
                }
                Err(e) => return Err(DurableError::Io(e)),
                Ok(bytes) => bytes,
            };
            let Some(records) = self.decode_commit_file(&bytes, seq) else {
                continue;
            };
            for record in records {
                facts.push(record);
            }
        }
        Ok(facts)
    }

    /// Decode one commit file: `None` means ignore the file (torn write,
    /// future version, or corrupt entry — never a partial state, since
    /// visibility is gated on CURRENT, not on file presence).
    fn decode_commit_file(&self, bytes: &[u8], seq: u64) -> Option<Vec<DecodedFact>> {
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Option<&[u8]> {
            let end = pos.checked_add(n)?;
            if end > bytes.len() {
                return None;
            }
            let slice = &bytes[*pos..end];
            *pos = end;
            Some(slice)
        };
        if take(&mut pos, 1)? != [COMMIT_VERSION] {
            return None;
        }
        if u64::from_le_bytes(take(&mut pos, 8)?.try_into().ok()?) != seq {
            return None;
        }
        let count = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
        let mut out = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let tag = take(&mut pos, 1)?[0];
            let len = u32::from_le_bytes(take(&mut pos, 4)?.try_into().ok()?) as usize;
            let record = take(&mut pos, len)?.to_vec();
            // Unknown tags are skipped for forward compatibility; a
            // malformed known record poisons the file, not the store.
            if !KNOWN_TAGS.contains(&tag) {
                continue;
            }
            out.push(self.decode_record(tag, &record)?);
        }
        if pos != bytes.len() {
            return None;
        }
        Some(out)
    }

    /// Decode one known record: `None` poisons the file (the caller
    /// filters unknown tags before calling).
    fn decode_record(&self, tag: u8, record: &[u8]) -> Option<DecodedFact> {
        match tag {
            TAG_TRANSITION => {
                let t = MembershipTransition::from_canonical_bytes(record).ok()?;
                Some(DecodedFact::Transition(t))
            }
            TAG_CAPABILITY => {
                if record.len() < 24 + 16 {
                    return None;
                }
                let nonce: &[u8; 24] = record[..24].try_into().ok()?;
                let pt = aead::open(
                    self.store_key.0.as_slice(),
                    nonce,
                    &record[24..],
                    &self.capability_aad(),
                )
                .ok()?;
                let cap = parse_capability_plaintext(&pt)?;
                if cap.drive != self.drive {
                    return None;
                }
                Some(DecodedFact::Capability(cap))
            }
            TAG_ANNOUNCEMENT => {
                let Message::SnapshotAnnouncement(a) =
                    Message::decode_payload(ControlKind::SnapshotAnnouncement, record).ok()?
                else {
                    return None;
                };
                Some(DecodedFact::Announcement(a))
            }
            TAG_MANIFEST => Some(DecodedFact::Manifest(parse_manifest_record(record)?)),
            TAG_LOCAL_OBJECT => {
                let id = ContentId::from_bytes(record.try_into().ok()?);
                Some(DecodedFact::LocalObject(id))
            }
            TAG_MATERIALIZATION => {
                if record.len() != 33 {
                    return None;
                }
                let id = ContentId::from_bytes(record[..32].try_into().ok()?);
                let state = match record[32] {
                    0 => MaterializationState::RemoteOnly,
                    1 => MaterializationState::Cached,
                    2 => MaterializationState::Pinned,
                    _ => return None,
                };
                Some(DecodedFact::Materialization(id, state))
            }
            TAG_CONTROL_MESSAGE => {
                let raw: [u8; 32] = record.try_into().ok()?;
                Some(DecodedFact::ControlMessage(ControlMessageId::from_bytes(
                    raw,
                )))
            }
            // Unreachable: the caller filters unknown tags.
            _ => None,
        }
    }

    /// Rebuild the live state: replay transitions into a fresh log,
    /// re-validate capabilities against their transition's derived state,
    /// install the local device's capabilities, and replay the runtime
    /// facts through the same mutators that accepted them.
    pub fn rebuild(&self, device: DeviceId) -> Result<Rebuilt, DurableError> {
        let facts = self.load()?;
        let mut log = MembershipLog::new(self.drive);
        for t in &facts.transitions {
            log.observe(t.clone());
        }
        let mut runtime = RuntimeState::new(self.drive);
        for a in facts.announcements {
            runtime.record_announcement(a)?;
        }
        for m in facts.manifests {
            runtime.record_manifest(m)?;
        }
        for id in facts.local_objects {
            runtime.mark_local_object(id);
        }
        for (id, state) in facts.materialization {
            runtime.set_materialization(id, state);
        }
        for id in facts.seen {
            runtime.remember_control_message(&id);
        }
        let mut keyring = DriveKeyring::new(self.drive, device);
        for cap in &facts.capabilities {
            if cap.device != device {
                // Single-device view: the store may hold facts for several
                // devices, but a keyring serves exactly one.
                continue;
            }
            let state = log
                .state_of(&cap.transition)
                .ok_or(DurableError::CapabilityTransitionUnknown)?;
            cap.validate_against(&state)
                .map_err(|_| DurableError::CapabilityChanged(cap.device))?;
            keyring.install(cap, &state)?;
        }
        Ok(Rebuilt {
            log,
            keyring,
            runtime,
        })
    }
}

// --- commit envelope ---------------------------------------------------------

/// Record tags this version understands. Unknown tags are skipped on
/// decode for forward compatibility.
const KNOWN_TAGS: [u8; 7] = [
    TAG_TRANSITION,
    TAG_CAPABILITY,
    TAG_ANNOUNCEMENT,
    TAG_MANIFEST,
    TAG_LOCAL_OBJECT,
    TAG_MATERIALIZATION,
    TAG_CONTROL_MESSAGE,
];

fn encode_commit(seq: u64, records: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(COMMIT_VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (tag, record) in records {
        out.push(*tag);
        out.extend_from_slice(&(record.len() as u32).to_le_bytes());
        out.extend_from_slice(record);
    }
    out
}

// --- capability plaintext ----------------------------------------------------

/// Parse sealed-capability plaintext back into a capability: exact
/// length, epoch equals the secret count, and `Capability::new`
/// re-checks the shape (curve point, non-empty, epoch binding).
fn parse_capability_plaintext(pt: &[u8]) -> Option<Capability> {
    if pt.len() < 140 || !(pt.len() - 140).is_multiple_of(32) {
        return None;
    }
    let epoch = u64::from_le_bytes(pt[128..136].try_into().ok()?);
    let count = u32::from_le_bytes(pt[136..140].try_into().ok()?) as u64;
    if epoch != count || pt.len() != 140 + count as usize * 32 {
        return None;
    }
    let secrets = pt[140..]
        .chunks_exact(32)
        .map(|c| EpochSecret::from_bytes(c.try_into().expect("chunks_exact(32)")))
        .collect();
    Capability::new(
        DriveId::from_bytes(pt[0..32].try_into().ok()?),
        DeviceId::from_bytes(pt[32..64].try_into().ok()?),
        DeviceEncryptionKey::from_bytes(pt[64..96].try_into().ok()?),
        TransitionId::from_bytes(pt[96..128].try_into().ok()?),
        epoch,
        secrets,
    )
    .ok()
}

fn parse_manifest_record(record: &[u8]) -> Option<ManifestRecord> {
    if record.len() < 32 + 1 + 4 {
        return None;
    }
    let manifest_id = ContentId::from_bytes(record[0..32].try_into().ok()?);
    let is_root = match record[32] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let storage_count = u32::from_le_bytes(record[33..37].try_into().ok()?) as usize;
    let mut pos: usize = 37;
    let mut storage_ids = std::collections::BTreeSet::new();
    for _ in 0..storage_count {
        let end = pos.checked_add(32)?;
        if end > record.len() {
            return None;
        }
        storage_ids.insert(StorageId::from_bytes(record[pos..end].try_into().ok()?));
        pos = end;
    }
    let manifest = Manifest::from_canonical_bytes(&record[pos..]).ok()?;
    let derived = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
    if manifest_id != derived {
        return None;
    }
    Some(ManifestRecord {
        is_root,
        manifest_id,
        storage_ids,
        manifest,
    })
}

// --- decoded facts -------------------------------------------------------------

#[derive(Debug, Clone)]
enum DecodedFact {
    Transition(MembershipTransition),
    Capability(Capability),
    Announcement(SnapshotAnnouncement),
    Manifest(ManifestRecord),
    LocalObject(ContentId),
    Materialization(ContentId, MaterializationState),
    ControlMessage(ControlMessageId),
}

impl LoadedFacts {
    fn push(&mut self, fact: DecodedFact) {
        match fact {
            DecodedFact::Transition(t) => self.transitions.push(t),
            DecodedFact::Capability(c) => self.capabilities.push(c),
            DecodedFact::Announcement(a) => self.announcements.push(a),
            DecodedFact::Manifest(m) => self.manifests.push(m),
            DecodedFact::LocalObject(id) => self.local_objects.push(id),
            DecodedFact::Materialization(id, s) => self.materialization.push((id, s)),
            DecodedFact::ControlMessage(id) => self.seen.push(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::test_util::{drive, key, Builder};
    use std::sync::atomic::{AtomicU64, Ordering};
    use wyrd_format::{ManifestEntry, SnapshotId};

    const PASSPHRASE: &str = "durable test passphrase";

    /// An isolated store directory, removed on drop. Unique per test
    /// (process id plus counter) since tests run multithreaded.
    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir()
                .join(format!("wyrd-durable-{name}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TestDir { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn owner() -> DeviceId {
        key(10).1
    }

    /// Genesis + one child, the fact stream's first two commits.
    fn chain() -> (MembershipTransition, MembershipTransition) {
        let (mut b, genesis) = Builder::genesis(10);
        let child = b.child(vec![wyrd_format::Change::Rotate]);
        (genesis, child)
    }

    fn authorized_capability(
        genesis: &MembershipTransition,
        log: &MembershipLog,
    ) -> AuthorizedCapability {
        let state = log
            .state_of(&genesis.transition_id())
            .expect("genesis has state");
        let cap = Capability::mint(
            drive(),
            owner(),
            &state,
            genesis.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0xAA; 32])],
        )
        .unwrap();
        AuthorizedCapability::authorize(cap, &state).unwrap()
    }

    fn announcement(child: &MembershipTransition) -> SnapshotAnnouncement {
        SnapshotAnnouncement {
            snapshot: SnapshotId::from_bytes([1; 32]),
            author: owner(),
            epoch: 2,
            membership: child.transition_id(),
        }
    }

    fn manifest_record() -> ManifestRecord {
        let manifest = Manifest {
            snapshot: SnapshotId::from_bytes([1; 32]),
            entries: vec![ManifestEntry {
                content_id: ContentId::from_bytes([4; 32]),
                kind: ObjectKind::Chunk,
                version: 0,
                storage_id: StorageId::from_bytes([0xA0; 32]),
                encryption_epoch: 1,
                size: 123,
            }],
            children: vec![],
        };
        let manifest_id = ContentId::derive(ObjectKind::Manifest, &manifest.canonical_bytes());
        ManifestRecord {
            is_root: true,
            manifest_id,
            storage_ids: [StorageId::from_bytes([0xA0; 32])].into(),
            manifest,
        }
    }

    /// The two-commit fact stream: A holds genesis, B holds everything
    /// else. Returns (A facts, B facts).
    fn fact_stream() -> (Vec<Fact>, Vec<Fact>) {
        let (genesis, child) = chain();
        let mut log = MembershipLog::new(drive());
        log.observe(genesis.clone());
        let a = vec![Fact::Transition(genesis.clone())];
        let b = vec![
            Fact::Transition(child.clone()),
            Fact::Announcement(announcement(&child)),
            Fact::Manifest(manifest_record()),
            Fact::Capability(authorized_capability(&genesis, &log)),
            Fact::LocalObject(ContentId::from_bytes([9; 32])),
            Fact::Materialization(ContentId::from_bytes([9; 32]), MaterializationState::Cached),
            Fact::ControlMessage(ControlMessageId::from_bytes([0xAB; 32])),
        ];
        (a, b)
    }

    const ALL_STAGES: [CrashStage; 8] = [
        CrashStage::AfterWriteTemp,
        CrashStage::AfterFsyncTemp,
        CrashStage::AfterRenameCommit,
        CrashStage::AfterFsyncCommitDir,
        CrashStage::AfterWriteCurrentTemp,
        CrashStage::AfterFsyncCurrentTemp,
        CrashStage::AfterRenameCurrent,
        CrashStage::Complete,
    ];

    /// The milestone property: a crash at any commit boundary reloads to
    /// the previous or the fully committed state — never a hybrid.
    #[test]
    fn crash_matrix_never_hybrid() {
        let (a, b) = fact_stream();
        // The fully committed reference, built in a parallel store so no
        // fact bytes are shared with the crashed stores.
        let expected_dir = TestDir::new("matrix-ref");
        let mut expected_store =
            DurableStore::open(expected_dir.path.clone(), drive(), PASSPHRASE).unwrap();
        expected_store.commit(&a).unwrap();
        expected_store.commit(&b).unwrap();
        let expected_before = {
            let dir = TestDir::new("matrix-before");
            let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
            store.commit(&a).unwrap();
            drop(store);
            let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
            store.load().unwrap()
        };
        let expected_full = expected_store.load().unwrap();

        for stage in ALL_STAGES {
            let dir = TestDir::new("matrix");
            let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
            store.commit(&a).unwrap();
            store.commit_until(&b, stage).unwrap();
            drop(store);
            let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
            let reloaded = store.load().unwrap();
            assert!(
                reloaded == expected_before || reloaded == expected_full,
                "stage {stage:?} reloaded a hybrid state"
            );
        }
    }

    /// Torn writes, orphaned temps, unknown tags, and trailing garbage
    /// are ignored; a missing commit at or below CURRENT fails loudly.
    #[test]
    fn torn_and_orphan_files_ignored() {
        let (a, _) = fact_stream();
        let dir = TestDir::new("torn");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        let commits = dir.path.join("commits");

        // Valid but empty commits 2..=6, so CURRENT may advance past them.
        for seq in 2..=6u64 {
            let bytes = encode_commit(seq, &[]);
            fs::write(commits.join(commit_name(seq)), &bytes).unwrap();
        }
        // Bad version, truncation, trailing garbage, future tag. Names
        // go through commit_name: sequences are hex, not decimal.
        fs::write(commits.join(commit_name(7)), b"junk").unwrap();
        let valid = encode_commit(8, &[(TAG_TRANSITION, b"short".to_vec())]);
        fs::write(commits.join(commit_name(8)), &valid[..10]).unwrap();
        let mut trailed = encode_commit(9, &[]);
        trailed.extend_from_slice(b"trailing");
        fs::write(commits.join(commit_name(9)), &trailed).unwrap();
        let future = encode_commit(10, &[(0x7F, b"future".to_vec())]);
        fs::write(commits.join(commit_name(10)), &future).unwrap();
        // Orphaned temps from a crashed predecessor.
        fs::write(commits.join("0000000000000004.commit.tmp"), b"partial").unwrap();
        fs::write(dir.path.join("CURRENT.tmp"), b"partial").unwrap();
        // Advance CURRENT past the debris: only commit 1 is real.
        atomic_write(&dir.path, "CURRENT", &10u64.to_le_bytes()).unwrap();

        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let reloaded = store.load().unwrap();
        assert_eq!(
            reloaded.transitions.len(),
            1,
            "only the real commit replays"
        );

        // A missing commit at or below CURRENT is damage, not a crash
        // artifact: fail loudly.
        fs::remove_file(commits.join("0000000000000001.commit")).unwrap();
        assert!(matches!(store.load(), Err(DurableError::MissingCommit(1))));
    }

    /// Facts rebuild the live machines bit-identically: same log
    /// verdicts, same keyring secrets, same runtime state and fetch plan
    /// as the in-memory path.
    #[test]
    fn facts_rebuild_live_state() {
        let (a, b) = fact_stream();
        let dir = TestDir::new("rebuild");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        store.commit(&b).unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let rebuilt = store.rebuild(owner()).unwrap();

        let (genesis, child) = chain();
        let mut log = MembershipLog::new(drive());
        log.observe(genesis.clone());
        log.observe(child.clone());
        assert_eq!(rebuilt.log.statuses(), log.statuses());
        assert_eq!(
            rebuilt.log.known_state().map(|k| k.epoch),
            Some(2),
            "rebuilt tip follows the replayed chain"
        );
        assert_eq!(
            rebuilt.keyring.secret(1).unwrap().as_bytes(),
            &[0xAA; 32],
            "rebuilt keyring holds the persisted epoch secret"
        );

        let mut runtime = RuntimeState::new(drive());
        runtime.record_announcement(announcement(&child)).unwrap();
        runtime.record_manifest(manifest_record()).unwrap();
        runtime.mark_local_object(ContentId::from_bytes([9; 32]));
        runtime.set_materialization(ContentId::from_bytes([9; 32]), MaterializationState::Cached);
        runtime.remember_control_message(&ControlMessageId::from_bytes([0xAB; 32]));
        assert_eq!(rebuilt.runtime, runtime);
        assert_eq!(
            rebuilt.runtime.reconcile().pending_objects.len(),
            0,
            "the persisted object is local, so nothing is queued"
        );
    }

    /// The type gate: a capability for a non-member can never become an
    /// authorized fact, so it can never reach the commit path.
    #[test]
    fn unauthorized_capability_cannot_commit() {
        let (genesis, _) = chain();
        let mut log = MembershipLog::new(drive());
        log.observe(genesis.clone());
        let state = log.state_of(&genesis.transition_id()).unwrap();
        let stranger = DeviceId::from_bytes([0x77; 32]);
        let cap = Capability::mint(
            drive(),
            stranger,
            &state,
            genesis.transition_id(),
            1,
            vec![EpochSecret::from_bytes([0xAA; 32])],
        );
        assert!(
            cap.is_err(),
            "minting for a non-member fails before authorization"
        );
    }

    /// A clean commit round-trips exactly: no crash, no loss.
    #[test]
    fn reload_without_crash_is_identity() {
        let (a, b) = fact_stream();
        let dir = TestDir::new("identity");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        let before = store.load().unwrap();
        store.commit(&b).unwrap();
        let committed = store.load().unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        assert_eq!(store.load().unwrap(), committed);
        assert_ne!(committed, before, "the second commit added facts");
        assert_eq!(store.current(), 2);
    }

    /// Open guards: another drive and another passphrase both fail.
    #[test]
    fn open_guards_identity_and_passphrase() {
        let (a, _) = fact_stream();
        let dir = TestDir::new("guards");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        drop(store);
        assert!(matches!(
            DurableStore::open(
                dir.path.clone(),
                DriveId::from_bytes([0x99; 32]),
                PASSPHRASE
            ),
            Err(DurableError::DriveMismatch)
        ));
        assert!(DurableStore::open(dir.path.clone(), drive(), "wrong passphrase").is_err());
        // The right passphrase still opens after the failed attempts.
        assert!(DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).is_ok());
    }

    /// Committing zero facts touches nothing.
    #[test]
    fn empty_commit_is_noop() {
        let dir = TestDir::new("empty");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        assert_eq!(store.commit(&[]).unwrap(), 0);
        assert_eq!(store.current(), 0);
    }
}
