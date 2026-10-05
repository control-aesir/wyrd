//! Store lifecycle and the crash-safe commit protocol: open, drive and
//! store-key initialization, CURRENT handling, atomic writes, commit
//! sequencing, and the fsync/rename ordering. A commit is visible only
//! when its sequence is at or below the durable CURRENT.

use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

use wyrd_format::{DeviceId, DriveId};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::codec::{
    decode_commit_file, encode_commit, encode_fact, MAX_COMMIT_BYTES, MAX_RECORDS_PER_COMMIT,
    STORE_KEY_AAD,
};
use super::replay::{self, LoadedFacts, Rebuilt};
use super::{DurableError, Fact};
use crate::keys::keystore::{kdf_key, KeystoreError, KDF_SALT_LEN};
use crate::keys::{aead, random_bytes};

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

/// The durable commit log for one drive. Single writer, enforced: an
/// exclusive advisory lock (`LOCK`, kernel-held for the store's
/// lifetime) rejects a second open of the same directory, so the
/// single-writer invariant no longer rests on discipline alone. No
/// `Debug`: the store key must never be printable.
pub struct DurableStore {
    dir: PathBuf,
    drive: DriveId,
    current: u64,
    /// The hash of the commit at `current` (zeros on a fresh store):
    /// the previous-hash link for the next commit.
    last_hash: [u8; 32],
    store_key: StoreKey,
    /// The locked lock-file handle; holding it keeps the advisory lock.
    /// Closed and released on drop — no stale locks survive a crash.
    _lock: File,
    /// Test-only delivery-pass accounting: counts `rebuild` calls so
    /// tests prove one snapshot per pass instead of one per pair.
    #[cfg(test)]
    rebuilds: AtomicU64,
}

/// Crate-visible for the raw-commit test seam alongside `atomic_write`.
pub(crate) fn commit_name(seq: u64) -> String {
    format!("{seq:016x}.commit")
}

pub(crate) fn fsync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Durably create-or-replace one file: temp + `fsync` + rename +
/// directory `fsync`. Fixed `.tmp` sibling; stale temps are overwritten,
/// never read.
pub(crate) fn atomic_write(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(name))?;
    fsync_dir(dir)
}

/// Owner-only file mode for custody secrets (`store-key.wrap`,
/// `keystore`, `pairing.secret`) and the store lock: no group or other
/// access, independent of the process umask.
pub(crate) const SECRET_FILE_MODE: u32 = 0o600;
/// Mode for the public drive-identity file: no wider than `0o644`
/// (readable by all, writable by the owner only). `DRIVE` is the drive
/// id, public by construction. The `open` mode is a ceiling masked by
/// the umask, so a strict umask lands a stricter file — never a
/// looser one.
const DRIVE_FILE_MODE: u32 = 0o644;
/// Owner-only mode for drive state directories. Unix-only in
/// practice (every use sits in a `#[cfg(unix)]` arm); referenced on
/// all platforms so the contract reads in one place.
#[cfg_attr(not(unix), allow(dead_code))]
const DRIVE_DIR_MODE: u32 = 0o700;

/// Create the atomic-write temp file with an explicit Unix mode, so a
/// crash between creation and rename never leaves a world-readable
/// temp holding custody bytes. The mode applies at creation only, so
/// the name is claimed (`create_new`) rather than truncated: reusing
/// a stale temp would carry its old loose mode through the rename. On
/// a lost race the stale file is removed once and the claim retried,
/// and a second failure propagates — the mode invariant is enforced,
/// not assumed. Creation is single-writer (the store lock), so a retry
/// meets a crashed predecessor's temp, never a live competitor.
/// Non-Unix falls back to `File::create_new`: the mode guarantee is
/// Unix-only (see `docs/cli.md`).
pub(crate) fn create_mode_temp(
    dir: &Path,
    name: &str,
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
) -> std::io::Result<File> {
    let tmp = dir.join(format!("{name}.tmp"));
    #[cfg(unix)]
    let claim = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
    };
    #[cfg(not(unix))]
    let claim = || File::create_new(&tmp);
    match claim() {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp)?;
            claim()
        }
        Err(error) => Err(error),
    }
}

/// Durably create-or-replace one custody file: temp (at an explicit
/// Unix `mode`, see [`create_mode_temp`]) + `fsync` + rename +
/// directory `fsync`. The rename preserves the temp's mode, so no
/// post-rename chmod — and no chmod-failure-after-rename outcome —
/// exists. Custody and identity files flow through here; operational
/// state (`CURRENT`, commits) keeps flowing through [`atomic_write`]:
/// creation hardens, opening never chmods.
pub(crate) fn atomic_write_mode(
    dir: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> std::io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    let mut f = create_mode_temp(dir, name, mode)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(name))?;
    fsync_dir(dir)
}

/// Create a drive state directory at no wider than owner-only
/// (`0o700`) when this call establishes the leaf, so the result never
/// exceeds the contract whatever the process umask. The mode is set on
/// the create call itself (`DirBuilder::mode`), not chmod'ed after: no
/// window exists where the leaf sits at the umask mode. Like every
/// `open` mode it is a ceiling masked by the umask — an
/// owner-masking umask lands a stricter leaf, never a looser one.
/// Freshness comes from the create call itself (`AlreadyExists` means a concurrent creator won), not from a
/// preceding stat, so no check-then-act gap exists. A pre-existing
/// directory is left untouched, and parents above the leaf are the
/// operator's business and keep their modes: creation hardens,
/// opening never chmods. Non-Unix falls back to plain
/// `create_dir_all` (see `docs/cli.md`).
pub(crate) fn ensure_owner_only_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(not(unix))]
    return fs::create_dir_all(path);
    #[cfg(unix)]
    {
        if path.is_dir() {
            return Ok(());
        }
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(DRIVE_DIR_MODE);
        match builder.create(path) {
            Ok(()) => return Ok(()),
            // A concurrent creator won the leaf — but `AlreadyExists`
            // is also a regular file or dangling symlink, so confirm
            // it is a directory and fail at the call that names it
            // when it is not.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if path.is_dir() {
                    return Ok(());
                }
                return Err(error);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // Parents were missing: create the chain at the operator's
        // modes, then restrict the leaf. A concurrent creator winning
        // the leaf in the gap keeps the lock-held fresh-DRIVE
        // restriction (drive dirs) as the backstop — and this call only
        // ever narrows modes, never widens them.
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(DRIVE_DIR_MODE))?;
        Ok(())
    }
}

/// Restrict a drive state directory to owner-only, whatever its
/// current mode. Called only when establishing fresh drive state in
/// it — initializing into a pre-existing empty directory still makes
/// it a custody directory. Never called when opening an established
/// drive, so pre-fix drives keep their modes. Non-Unix: no-op (see
/// `docs/cli.md`).
pub(crate) fn restrict_dir_owner_only(
    #[cfg_attr(not(unix), allow(unused_variables))] path: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(DRIVE_DIR_MODE))?;
    Ok(())
}

impl DurableStore {
    /// The drive directory the store lives in.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    fn commits_dir(&self) -> PathBuf {
        self.dir.join("commits")
    }

    /// Open (or create) the store: verify the drive id, unwrap or mint
    /// the store key, read CURRENT. Missing CURRENT means a fresh store.
    /// The CURRENT marker is trusted on open and verified on load.
    pub fn open(dir: PathBuf, drive: DriveId, passphrase: &str) -> Result<Self, DurableError> {
        // Drive state directories are owner-only from creation, never
        // the umask's business. Leaves this call created are restricted
        // here; fresh drive state in a pre-existing directory is
        // restricted at the DRIVE write below. Opening an established
        // drive never chmods.
        ensure_owner_only_dir(&dir)?;
        let commits = dir.join("commits");
        ensure_owner_only_dir(&commits)?;
        // Exclusive ownership before any store state is read or written
        // (the directory itself is created idempotently above). The lock
        // is a kernel-held flock on LOCK: it dies with this process, so
        // a crash leaves no stale lock to clean up. The handle is held
        // for the store's lifetime and released on drop. The lock guards
        // cooperating callers — every open runs through here; the
        // commit chain still detects damage from non-cooperating
        // writers, it never serialized them.
        //
        // LOCK is created owner-only: a world-writable lock lets another
        // local user interfere with the exclusive-ownership guarantee
        // this open exists to provide. An existing lock keeps its mode.
        let mut lock_opts = File::options();
        lock_opts
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        lock_opts.mode(SECRET_FILE_MODE);
        let lock = lock_opts.open(dir.join("LOCK"))?;
        match lock.try_lock() {
            Ok(()) => {}
            // Definite contention: another holder owns the directory.
            Err(std::fs::TryLockError::WouldBlock) => return Err(DurableError::StoreLocked),
            // Anything else is an operational failure, not contention.
            Err(std::fs::TryLockError::Error(error)) => return Err(DurableError::Io(error)),
        }
        // Drive identity, written once: a store directory never changes drives.
        // A missing DRIVE means fresh drive state is being established
        // in this directory — it becomes a custody directory now even
        // when it pre-existed (init into an existing empty dir), so
        // restrict it. An existing DRIVE means an established drive
        // whose modes are never touched.
        let drive_path = dir.join("DRIVE");
        match fs::read(&drive_path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                restrict_dir_owner_only(&dir)?;
                restrict_dir_owner_only(&commits)?;
                atomic_write_mode(&dir, "DRIVE", drive.as_bytes(), DRIVE_FILE_MODE)?;
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
            _lock: lock,
            #[cfg(test)]
            rebuilds: AtomicU64::new(0),
        })
    }

    /// The last durable commit sequence.
    pub fn current(&self) -> u64 {
        self.current
    }

    /// Bytes of commit files on disk, counted without touching
    /// anything. The observational half of retention reporting: the
    /// fact log is resident but unenforced, so `cache policy` shows
    /// this next to the quota-enforced object-store count rather than
    /// folding it in. Read-only like
    /// [`wyrd_format::FsObjectStore::retained_bytes`]: temp files
    /// (`.tmp`, a crashed commit's debris) are excluded, and a missing
    /// commits directory counts as zero.
    pub fn committed_bytes(&self) -> Result<u64, DurableError> {
        let mut total = 0u64;
        let entries = match fs::read_dir(self.commits_dir()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(DurableError::Io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(DurableError::Io)?;
            // One stat per entry: `metadata` answers both questions —
            // kind and length — and follows symlinks, like the walk
            // this replaced. A file that vanishes first was never ours
            // to count; any other listing failure is operational.
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(DurableError::Io(error)),
            };
            if !metadata.is_file() {
                continue;
            }
            if entry.path().extension().is_some_and(|ext| ext == "tmp") {
                continue;
            }
            total += metadata.len();
        }
        Ok(total)
    }

    /// Test-only: release the advisory lock without dropping the store,
    /// modeling an abrupt process death (a restart test's fresh engine
    /// opens the directory while the parked old engine is still in
    /// scope, holding an unlocked store it never touches again).
    #[cfg(test)]
    pub(crate) fn release_store_lock(&self) {
        let _ = self._lock.unlock();
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
                atomic_write_mode(dir, "store-key.wrap", &bytes, SECRET_FILE_MODE)?;
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
        // Refuse before writing what load would reject. Both load
        // ceilings bind here: the record count (checked below, ahead
        // of the encode loop) and the encoded byte size (checked
        // after `encode_commit`, covering batches inside the count
        // that mix many records with large ones). Either would
        // otherwise advance CURRENT onto a commit no reopen could
        // read — wedging the drive instead of the batch. The policy
        // commit batch is the first caller whose fact count is a
        // function of an operator-named path rather than a live
        // budget, which is why the checks live here for every
        // committer instead of at one call site.
        check_commit_fits(facts.len(), 0)?;
        // Refresh against disk: a crashed predecessor may have advanced
        // CURRENT further than this handle saw.
        let (disk_current, disk_hash) = Self::read_current(&self.dir)?;
        if disk_current > self.current {
            self.current = disk_current;
            self.last_hash = disk_hash;
        }
        let mut records = Vec::with_capacity(facts.len());
        for fact in facts {
            records.push(encode_fact(self.store_key.0.as_slice(), &self.drive, fact)?);
        }
        let seq = self
            .current
            .checked_add(1)
            .ok_or(DurableError::SequenceExhausted)?;
        let (bytes, hash) = encode_commit(&self.drive, seq, &self.last_hash, &records);
        // `records.len()` is the count the encoder wrote and the
        // decoder reads back — not `facts.len()` by assumption.
        check_commit_fits(records.len(), bytes.len())?;
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
            let (records, hash) = decode_commit_file(
                &self.drive,
                self.store_key.0.as_slice(),
                &bytes,
                seq,
                &prev_hash,
            )?;
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

    /// Rebuild the live state from the durable facts. Delegates to
    /// [`replay`]: transitions replay first, capabilities re-validate
    /// against their transition's derived state, then the runtime facts
    /// replay through the same mutators that accepted them.
    ///
    /// [`replay`]: mod@replay
    pub fn rebuild(&self, device: DeviceId) -> Result<Rebuilt, DurableError> {
        #[cfg(test)]
        self.rebuilds.fetch_add(1, Ordering::Relaxed);
        let facts = self.load()?;
        replay::rebuild_facts(&self.drive, facts, device)
    }

    /// Test-only: how many `rebuild` calls this store has served.
    #[cfg(test)]
    pub(crate) fn rebuild_count(&self) -> u64 {
        self.rebuilds.load(Ordering::Relaxed)
    }
}

/// Refuse before writing what load would reject. Both ceilings bind
/// on the read path, so advancing CURRENT past either wedges the
/// drive instead of the batch: the record count is checked ahead of
/// the encode loop (callers pass 0 bytes there), the encoded size
/// after `encode_commit`. Pure so the boundaries stay unit-tested
/// without allocating a 64 MiB commit.
pub(super) fn check_commit_fits(records: usize, bytes: usize) -> Result<(), DurableError> {
    if records > MAX_RECORDS_PER_COMMIT {
        return Err(DurableError::TooManyRecords {
            count: records,
            max: MAX_RECORDS_PER_COMMIT,
        });
    }
    if bytes as u64 > MAX_COMMIT_BYTES {
        return Err(DurableError::CommitTooLarge {
            bytes: bytes as u64,
            max: MAX_COMMIT_BYTES,
        });
    }
    Ok(())
}
