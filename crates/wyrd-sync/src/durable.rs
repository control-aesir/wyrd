//! Durable local state: an append-only commit log with an atomic commit
//! marker (durable-state issue).
//!
//! Layout under one drive directory:
//!
//! ```text
//! drive/
//!   DRIVE              32-byte drive id, written once at creation
//!   store-key.wrap     store key sealed under the passphrase
//!   CURRENT            sequence (8-byte LE) plus commit hash (32 bytes)
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
//! and verifies each against the hash chain before replaying it.
//!
//! Failure semantics, stated exactly:
//!
//! ```text
//! orphaned .tmp files ............ ignore (never crossed the boundary)
//! commits above CURRENT .......... ignore (leave for GC)
//! commit <= CURRENT, valid ....... replay
//! commit <= CURRENT, missing ..... ERROR (store damage)
//! commit <= CURRENT, undecodable . ERROR (store damage, never a skip)
//! ```
//!
//! A torn write can only ever produce an orphaned temp: renames are
//! atomic and CURRENT advances only after the commit file and its
//! directory entry are durable. So corruption inside the committed
//! prefix is damage or tampering, and the load fails rather than
//! reconstructing a hybrid state around it.
//!
//! Integrity: each commit carries the BLAKE3 hash of the domain tag,
//! the drive id, its sequence, the previous commit's hash, and the
//! canonical records; CURRENT binds the tip hash. Recovery verifies the
//! whole chain, so the durable log is content-addressed end to end:
//!
//! ```text
//! CURRENT(seq, hash)
//!    ↓
//! commit N ──hash──> ... ──hash──> commit 1 ──hash──> zeros
//! ```
//!
//! Facts, not state — precisely, immutable mutations: commits carry
//! canonical records (transitions, sealed capabilities, announcements,
//! manifests) plus residency mutations (materialization entries are
//! last-wins, local-object marks are ever-local until a future removal
//! mutation exists). Loading replays them into a [`MembershipLog`], a
//! [`DriveKeyring`], and a [`RuntimeState`]; the caller runs
//! `reconcile()` for the fetch plan. Replay runs in dependency phases
//! (transitions first, then the rest), so the per-type buckets of
//! [`LoadedFacts`] reflect the replay structure; order is preserved
//! within each bucket. Derived indexes are rebuilt, never persisted, so
//! two representations of the same DAG can never disagree.
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

/// Resource limits: a corrupt local file must not cause unbounded
/// allocation. Commits hold small canonical facts; anything beyond
/// these bounds is damage, not data.
const MAX_COMMIT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS_PER_COMMIT: usize = 65_536;
const MAX_RECORD_BYTES: usize = 64 * 1024 * 1024;

/// Domain tag for the commit-chain hash: integrity and ordering of the
/// durable log itself, not confidentiality.
const COMMIT_HASH_DOMAIN: &[u8] = b"wyrd durable commit v1";
// The chain genesis: commit 1 links from all-zero bytes.

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
    #[error("CURRENT is present but not a sequence plus commit hash")]
    CorruptCurrent,
    #[error("commit {0} is present but undecodable")]
    CorruptCommit(u64),
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
    #[error("commit sequence exhausted")]
    SequenceExhausted,
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
    /// The hash of the commit at `current` (zeros on a fresh store):
    /// the previous-hash link for the next commit.
    last_hash: [u8; 32],
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
    /// The CURRENT marker is trusted on open and verified on load.
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
        let (current, last_hash) = Self::read_current(&dir)?;
        Ok(DurableStore {
            dir,
            drive,
            current,
            last_hash,
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

    /// Read the CURRENT marker: sequence plus tip hash. Missing means a
    /// fresh store; anything else malformed fails — CURRENT is only ever
    /// written atomically, so a partial marker is damage, not a crash
    /// artifact.
    fn read_current(dir: &Path) -> Result<(u64, [u8; 32]), DurableError> {
        match fs::read(dir.join("CURRENT")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((0, [0; 32])),
            Ok(bytes) => {
                if bytes.len() != 40 {
                    return Err(DurableError::CorruptCurrent);
                }
                let seq = u64::from_le_bytes(bytes[..8].try_into().expect("length checked"));
                let hash = bytes[8..40].try_into().expect("length checked");
                Ok((seq, hash))
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

    /// The tip hash for crafting chained commit files in tests.
    #[cfg(test)]
    pub(crate) fn tip_hash_for_test(&self) -> [u8; 32] {
        self.last_hash
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
        let (disk_current, disk_hash) = Self::read_current(&self.dir)?;
        if disk_current > self.current {
            self.current = disk_current;
            self.last_hash = disk_hash;
        }
        let mut records = Vec::with_capacity(facts.len());
        for fact in facts {
            records.push(self.encode_fact(fact)?);
        }
        let seq = self
            .current
            .checked_add(1)
            .ok_or(DurableError::SequenceExhausted)?;
        let (bytes, hash) = encode_commit(&self.drive, seq, &self.last_hash, &records);
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
        let current_tmp = self.dir.join("CURRENT.tmp");
        {
            let mut current_bytes = Vec::with_capacity(40);
            current_bytes.extend_from_slice(&seq.to_le_bytes());
            current_bytes.extend_from_slice(&hash);
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
        self.last_hash = hash;
        if stop == CrashStage::AfterRenameCurrent {
            return Ok(seq);
        }
        fsync_dir(&self.dir)?;
        Ok(seq)
    }

    /// Replay commits `1..=CURRENT` into facts, verifying the hash chain
    /// as it goes. Orphaned `.tmp` files and commits above CURRENT are
    /// ignored; anything else wrong — a missing commit, an undecodable
    /// commit, a broken hash link, a tip hash that disagrees with CURRENT
    /// — fails the load. A commit at or below CURRENT is authoritative;
    /// the loader never reconstructs around it.
    pub fn load(&self) -> Result<LoadedFacts, DurableError> {
        let (current, tip_hash) = Self::read_current(&self.dir)?;
        let mut facts = LoadedFacts::default();
        let mut prev_hash = [0u8; 32];
        for seq in 1..=current {
            let path = self.commits_dir().join(commit_name(seq));
            // Bound the read before allocating: the file must exist at
            // this size for the commit to be real.
            let size = fs::metadata(&path)
                .map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        DurableError::MissingCommit(seq)
                    } else {
                        DurableError::Io(e)
                    }
                })?
                .len();
            if size > MAX_COMMIT_BYTES {
                return Err(DurableError::CorruptCommit(seq));
            }
            let bytes = fs::read(&path).map_err(DurableError::Io)?;
            let (records, hash) = self.decode_commit_file(&bytes, seq, &prev_hash)?;
            prev_hash = hash;
            for record in records {
                facts.push(record);
            }
        }
        if prev_hash != tip_hash {
            return Err(DurableError::CorruptCurrent);
        }
        Ok(facts)
    }

    /// Decode and verify one commit file. Every structural failure —
    /// wrong version, sequence or previous-hash mismatch, over-limit
    /// counts or lengths, malformed known records, trailing bytes, a
    /// hash mismatch — fails the file: inside the committed prefix
    /// there is no such thing as an ignorable commit. Unknown record
    /// tags are the only skips, for forward compatibility.
    fn decode_commit_file(
        &self,
        bytes: &[u8],
        seq: u64,
        prev_hash: &[u8; 32],
    ) -> Result<(Vec<DecodedFact>, [u8; 32]), DurableError> {
        let corrupt = || DurableError::CorruptCommit(seq);
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
        if take(&mut pos, 1).ok_or_else(&corrupt)? != [COMMIT_VERSION] {
            return Err(corrupt());
        }
        if u64::from_le_bytes(
            take(&mut pos, 8)
                .ok_or_else(&corrupt)?
                .try_into()
                .expect("take"),
        ) != seq
        {
            return Err(corrupt());
        }
        if take(&mut pos, 32).ok_or_else(&corrupt)? != prev_hash {
            return Err(corrupt());
        }
        let count = u32::from_le_bytes(
            take(&mut pos, 4)
                .ok_or_else(&corrupt)?
                .try_into()
                .expect("take"),
        ) as usize;
        if count > MAX_RECORDS_PER_COMMIT {
            return Err(corrupt());
        }
        let mut out = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let tag = take(&mut pos, 1).ok_or_else(&corrupt)?[0];
            let len = u32::from_le_bytes(
                take(&mut pos, 4)
                    .ok_or_else(&corrupt)?
                    .try_into()
                    .expect("take"),
            ) as usize;
            if len > MAX_RECORD_BYTES {
                return Err(corrupt());
            }
            let record = take(&mut pos, len).ok_or_else(&corrupt)?.to_vec();
            if !KNOWN_TAGS.contains(&tag) {
                continue;
            }
            out.push(self.decode_record(tag, &record).ok_or_else(&corrupt)?);
        }
        // The trailer hash sits exactly at the end: no trailing bytes.
        if pos.checked_add(32) != Some(bytes.len()) {
            return Err(corrupt());
        }
        let expected = commit_hash(&self.drive, seq, prev_hash, &bytes[HEADER_LEN..pos]);
        let trailer: &[u8; 32] = bytes[pos..].try_into().expect("trailer bounds");
        if trailer != &expected {
            return Err(corrupt());
        }
        Ok((out, expected))
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

/// Commit header length: version (1) + sequence (8) + previous hash (32).
/// The records section hashed into the trailer starts right after it.
const HEADER_LEN: usize = 41;

/// The chain hash of one commit: domain tag, drive id, sequence,
/// previous hash, and the exact serialized records section. Binds
/// integrity and ordering; confidentiality is not the point (secrets
/// carry their own AEAD inside capability records).
fn commit_hash(drive: &DriveId, seq: u64, prev: &[u8; 32], records: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMIT_HASH_DOMAIN);
    hasher.update(drive.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev);
    hasher.update(records);
    *hasher.finalize().as_bytes()
}

/// Serialize one commit and hash it: header (version, sequence,
/// previous hash) + records + trailer hash.
fn encode_commit(
    drive: &DriveId,
    seq: u64,
    prev: &[u8; 32],
    records: &[(u8, Vec<u8>)],
) -> (Vec<u8>, [u8; 32]) {
    let mut records_bytes = Vec::new();
    records_bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (tag, record) in records {
        records_bytes.push(*tag);
        records_bytes.extend_from_slice(&(record.len() as u32).to_le_bytes());
        records_bytes.extend_from_slice(record);
    }
    let hash = commit_hash(drive, seq, prev, &records_bytes);
    let mut out = Vec::with_capacity(HEADER_LEN + records_bytes.len() + 32);
    out.push(COMMIT_VERSION);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(prev);
    out.extend_from_slice(&records_bytes);
    out.extend_from_slice(&hash);
    (out, hash)
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
    use crate::membership::test_util::{admit, drive, key, sign, Builder};
    use std::sync::atomic::{AtomicU64, Ordering};
    use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{Change, ManifestEntry, SnapshotId};

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

    /// Outside the committed prefix, debris is harmless: orphaned temps
    /// and commits above CURRENT are ignored, and only commit 1 replays.
    #[test]
    fn orphan_files_are_ignored() {
        let (a, _) = fact_stream();
        let dir = TestDir::new("orphans");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&a).unwrap();
        let commits = dir.path.join("commits");

        // Orphaned temps from a crashed predecessor, plus a commit file
        // above CURRENT (left for GC, never replayed — contents unread).
        fs::write(commits.join("0000000000000002.commit.tmp"), b"partial").unwrap();
        fs::write(dir.path.join("CURRENT.tmp"), b"partial").unwrap();
        fs::write(commits.join(commit_name(2)), b"future commit").unwrap();

        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let reloaded = store.load().unwrap();
        assert_eq!(
            reloaded.transitions.len(),
            1,
            "only the committed prefix replays"
        );
    }

    /// Inside the committed prefix, corruption fails the load: a damaged
    /// committed file is store damage, not an ignorable crash artifact.
    /// Pristine bytes are restored between cases.
    #[test]
    fn committed_corruption_fails() {
        let (genesis, child) = chain();
        let announcement = announcement(&child);
        let dir = TestDir::new("corrupt");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&[Fact::Transition(genesis)]).unwrap();
        store.commit(&[Fact::Transition(child)]).unwrap();
        let h2 = store.tip_hash_for_test();
        store.commit(&[Fact::Announcement(announcement)]).unwrap();
        let commits = dir.path.join("commits");
        drop(store);

        let pristine: Vec<Vec<u8>> = [1u64, 2, 3]
            .iter()
            .map(|seq| fs::read(commits.join(commit_name(*seq))).unwrap())
            .collect();
        let restore = || {
            for (seq, bytes) in [1u64, 2, 3].iter().zip(&pristine) {
                fs::write(commits.join(commit_name(*seq)), bytes).unwrap();
            }
        };
        let load = || {
            DurableStore::open(dir.path.clone(), drive(), PASSPHRASE)
                .unwrap()
                .load()
        };

        // A valid commit carrying only an unknown tag replays (the tag is
        // skipped); everything else below fails. Replacing the file
        // changes its hash, so CURRENT is re-anchored to the new tip —
        // exactly what a real commit would have written.
        let orig_current = fs::read(dir.path.join("CURRENT")).unwrap();
        let (tagged, hash3) = encode_commit(&drive(), 3, &h2, &[(0x7F, b"future".to_vec())]);
        fs::write(commits.join(commit_name(3)), &tagged).unwrap();
        let mut current = 3u64.to_le_bytes().to_vec();
        current.extend_from_slice(&hash3);
        atomic_write(&dir.path, "CURRENT", &current).unwrap();
        let reloaded = load().unwrap();
        assert_eq!(
            reloaded.transitions.len(),
            2,
            "unknown tags are skipped, valid facts replay"
        );
        restore();
        atomic_write(&dir.path, "CURRENT", &orig_current).unwrap();

        // Corrupt the middle commit: hybrid states must never load.
        let mut bad = pristine[1].clone();
        bad[50] ^= 1;
        fs::write(commits.join(commit_name(2)), &bad).unwrap();
        assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
        restore();

        // Corrupt the tip commit's trailer hash.
        let mut bad = pristine[2].clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        fs::write(commits.join(commit_name(3)), &bad).unwrap();
        assert!(matches!(load(), Err(DurableError::CorruptCommit(3))));
        restore();

        // Corrupt the header (version byte).
        let mut bad = pristine[1].clone();
        bad[0] = 0xFF;
        fs::write(commits.join(commit_name(2)), &bad).unwrap();
        assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
        restore();

        // Truncate a known record.
        let cut = pristine[1].len() - 40;
        fs::write(commits.join(commit_name(2)), &pristine[1][..cut]).unwrap();
        assert!(matches!(load(), Err(DurableError::CorruptCommit(2))));
        restore();

        // Delete the tip commit.
        fs::remove_file(commits.join(commit_name(3))).unwrap();
        assert!(matches!(load(), Err(DurableError::MissingCommit(3))));
        restore();

        // After all damage is repaired, the store loads cleanly.
        assert_eq!(load().unwrap().transitions.len(), 2);
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

    /// Hand-build a signed transition against the builder's drive and
    /// owner key, mirroring the membership suites: for siblings the
    /// builder cannot produce.
    #[allow(clippy::too_many_arguments)]
    fn signed(
        b: &Builder,
        epoch: u64,
        prev: Option<TransitionId>,
        resolves: Vec<TransitionId>,
        changes: Vec<Change>,
        members: &[DeviceId],
        owners: &[DeviceId],
        author_sk: &secp256k1::SecretKey,
        author: DeviceId,
    ) -> MembershipTransition {
        let mut t = MembershipTransition {
            epoch,
            prev,
            resolves,
            changes,
            members_root: set_root(MEMBER_SET_CONTEXT, members),
            owners_root: set_root(OWNER_SET_CONTEXT, owners),
            author,
            signature: [0; 64],
        };
        sign(&mut t, author_sk, &b.drive);
        t
    }

    /// Persistence against a nontrivial history: a fork with an explicit
    /// resolution rebuilds to the same verdicts, tip, and derived states
    /// as the live log — the replay is not just a linear-chain trick.
    #[test]
    fn fork_history_rebuilds_verdicts() {
        let (b, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();
        let own = owner();
        let (sk_owner, _) = key(10);
        let members = [own];
        // Two valid siblings at epoch 2: Rotate vs admitting device(5).
        let fork_rotate = signed(
            &b,
            2,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &members,
            &members,
            &sk_owner,
            own,
        );
        let forked = [own, DeviceId::from_bytes([5; 32])];
        let fork_admit = signed(
            &b,
            2,
            Some(genesis_id),
            Vec::new(),
            vec![admit(forked[1])],
            &forked,
            &members,
            &sk_owner,
            own,
        );
        // The Rotate sibling wins; the resolution names the loser.
        let resolution = signed(
            &b,
            3,
            Some(fork_rotate.transition_id()),
            vec![fork_admit.transition_id()],
            vec![Change::Rotate],
            &members,
            &members,
            &sk_owner,
            own,
        );

        let dir = TestDir::new("fork");
        let mut store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        store.commit(&[Fact::Transition(genesis.clone())]).unwrap();
        store
            .commit(&[
                Fact::Transition(fork_rotate.clone()),
                Fact::Transition(fork_admit.clone()),
                Fact::Transition(resolution.clone()),
            ])
            .unwrap();
        drop(store);
        let store = DurableStore::open(dir.path.clone(), drive(), PASSPHRASE).unwrap();
        let rebuilt = store.rebuild(owner()).unwrap();

        let mut log = MembershipLog::new(drive());
        for t in [&genesis, &fork_rotate, &fork_admit, &resolution] {
            log.observe((*t).clone());
        }
        use crate::membership::TransitionStatus;
        assert_eq!(rebuilt.log.statuses(), log.statuses());
        assert_eq!(
            rebuilt.log.status(&fork_rotate.transition_id()),
            Some(TransitionStatus::Canonical)
        );
        assert_eq!(
            rebuilt.log.status(&fork_admit.transition_id()),
            Some(TransitionStatus::Voided)
        );
        assert_eq!(
            rebuilt.log.status(&resolution.transition_id()),
            Some(TransitionStatus::Canonical)
        );
        assert_eq!(
            rebuilt.log.known_state().map(|k| k.epoch),
            Some(3),
            "rebuilt tip follows the resolution"
        );
        assert_eq!(
            rebuilt.log.state_of(&resolution.transition_id()),
            log.state_of(&resolution.transition_id())
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
