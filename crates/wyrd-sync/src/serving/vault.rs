use std::path::{Path, PathBuf};
use std::sync::Mutex;

use thiserror::Error;
use wyrd_format::durable;
use wyrd_format::BaoRoot;

use super::mirror::{MirrorSender, MirrorStats};
use crate::seal::blob_root;

/// The vault directory inside a drive directory.
const VAULT_DIR: &str = "vault";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// The serving mirror queue is full: the vault file is durable
    /// (the rename happened before write-through), but the mirror has
    /// not accepted these bytes. Retry the import on a later pass;
    /// the readiness barrier reports not-ready until the drain
    /// catches up, and a restart rebuilds the mirror from the vault.
    /// Per-item backpressure, never a batch wedge (see
    /// `docs/error-conventions.md`). Carries the refused transport
    /// root so a rejection traces to its publication.
    #[error("serving mirror queue full for {root}: {queued_bytes}/{max_bytes} bytes in {queued_items} items, rejected {rejected}")]
    MirrorFull {
        root: BaoRoot,
        queued_items: usize,
        queued_bytes: usize,
        max_bytes: usize,
        rejected: u64,
    },
}

/// A raw byte CAS with no authorization semantics: it stores and serves
/// bytes under their own hash, for whoever is allowed to reach the
/// drive's ciphertext at all. Authorization lives one layer up —
/// [`VaultSource`](super::source::VaultSource) offers only representations durably recorded by the
/// runtime machines, and every fetch still passes the AEAD/identity
/// admission checks before plaintext is trusted.
/// The drive's sealed representation store: one file per transport root,
/// named by the root's hex, written atomically and never rewritten.
pub struct Vault {
    pub(crate) dir: PathBuf,
    /// The live serving mirror's bounded write-through sender, attached
    /// by [`ServingEndpoint::open`](super::endpoint::ServingEndpoint::open) and replaced (never co-held) on
    /// reopen. Imports enqueue after the durable rename, so the vault
    /// stays the source of truth and the mirror is a derived,
    /// self-healing cache: a detached channel or a failed mirror import
    /// only delays serving until the next boot rebuild, while a full
    /// queue applies backpressure at import time (never a silent drop).
    /// The slot is shared (`Arc`) so the endpoint can detach it on
    /// shutdown: an import after shutdown must not enqueue into a
    /// channel nobody will drain.
    pub(crate) mirror: std::sync::Arc<Mutex<Option<MirrorSender>>>,
    /// Publication durability and its pending-directory recovery state.
    /// Production uses [`durable::fsync_dir`]; tests replace it to inject
    /// a post-rename durability failure and exercise the recovery path.
    pub(crate) durability: durable::Durability,
}

/// Unique temp-file suffix so concurrent imports of the same root never
/// share a scratch path (same-root importers race only at the atomic
/// rename, where the bytes are identical by construction).
static NEXT_TMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Vault {
    /// Open (or create) the vault directory under a drive directory.
    /// The leaf is established owner-only when this call creates it,
    /// never the umask's business; a pre-existing directory keeps its
    /// mode — creation hardens, opening never chmods, the same
    /// contract the custody files follow.
    pub fn open(drive_dir: &Path) -> Result<Self, VaultError> {
        let dir = drive_dir.join(VAULT_DIR);
        crate::durable::ensure_owner_only_dir(&dir)?;
        Ok(Vault {
            dir,
            mirror: std::sync::Arc::new(Mutex::new(None)),
            durability: durable::Durability::new(),
        })
    }

    /// The mirror slot, shared with the serving endpoint that owns the
    /// drain task. The endpoint clears it on shutdown.
    pub(crate) fn mirror_slot(&self) -> std::sync::Arc<Mutex<Option<MirrorSender>>> {
        std::sync::Arc::clone(&self.mirror)
    }

    /// Bytes of sealed representations on disk, counted without
    /// touching anything. The observational half of retention
    /// reporting alongside the fact log: the vault is resident but
    /// unenforced, so `cache policy` shows this next to the
    /// quota-enforced object-store count rather than folding it in.
    /// Import scratch files (`.tmp-*`, a crashed import's debris) are
    /// excluded — they are not servable representations — and a missing
    /// vault directory counts as zero.
    pub fn resident_bytes(&self) -> Result<u64, VaultError> {
        let mut total = 0u64;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(VaultError::Io(error)),
        };
        for entry in entries {
            let entry = entry.map_err(VaultError::Io)?;
            // One stat per entry: `metadata` answers both questions —
            // kind and length. `DirEntry::metadata` does not traverse
            // symlinks, so a symlink inside the vault directory is
            // excluded from the observational count rather than
            // followed out of the measured tree. A file that vanishes
            // first was never ours to count; any other listing failure
            // is operational.
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(VaultError::Io(error)),
            };
            if !metadata.is_file() {
                continue;
            }
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|name| name.as_encoded_bytes().starts_with(b".tmp-"))
            {
                continue;
            }
            total += metadata.len();
        }
        Ok(total)
    }

    /// Import sealed bytes: the file name is the bytes' own transport
    /// root, so the address handed out is exactly what the transfer
    /// verifies against. Importing an already-held root is a no-op —
    /// objects are immutable and the store is append-only. The temp file
    /// is scoped to the root (distinct roots never collide on the temp
    /// path), and the rename is the publication point: a torn write
    /// leaves a temp file, never a servable root. Publication uses the
    /// same crash protocol as the object store (temp + `fsync` + rename +
    /// directory `fsync`, `wyrd_format::durable`), so the new directory
    /// entry, not just the ciphertext, survives a power failure.
    ///
    /// The rename and the directory `fsync` are distinct stages. A rename
    /// failure leaves nothing published, but a directory-`fsync` failure
    /// leaves the file installed and not known durable; that error is
    /// surfaced, and a retry takes the held-root path, which re-syncs the
    /// directory and re-imports into the mirror. Both are idempotent, so a
    /// crash between the rename and the mirror write-through heals too.
    pub fn import(&self, sealed: &[u8]) -> Result<BaoRoot, VaultError> {
        let root = blob_root(sealed);
        let path = self.path(&root);
        // Repair any directory whose earlier publication failed its
        // fsync before deciding the import is a no-op.
        self.durability.reconcile()?;
        if path.is_file() {
            self.reconcile_held(root, sealed)?;
            return Ok(root);
        }
        let tmp = self.dir.join(format!(
            ".tmp-{}-{}-{}",
            root,
            std::process::id(),
            NEXT_TMP.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        self.durability.write_temp(&tmp, sealed)?;
        match self.durability.publish_temp(&tmp, &path) {
            Ok(()) => {}
            Err(durable::PublishError::Rename(error)) => {
                let _ = std::fs::remove_file(&tmp);
                // A concurrent import of the same root may have published
                // first; identical bytes hash to the same root, so the
                // existing file is the winner and this call reconciles
                // instead of failing.
                if path.is_file() {
                    self.reconcile_held(root, sealed)?;
                    return Ok(root);
                }
                return Err(error.into());
            }
            Err(durable::PublishError::DirectorySync(error)) => {
                // The rename installed the file but its directory entry is
                // not known durable. Notify the mirror best-effort so the
                // failure does not also strand serving readiness, then
                // surface the durability error; a retry re-syncs the
                // directory. Best-effort is literal here: even a full
                // queue — and even a poisoned slot — must not outrank
                // the error the caller was promised. The retry's
                // held-root path re-imports into the mirror once the
                // drain has room, and still surfaces a poisoned slot
                // through that path.
                let _ = self.notify_mirror(root, sealed);
                return Err(error.into());
            }
        }
        self.notify_mirror(root, sealed)?;
        Ok(root)
    }

    /// Make an already-held root durable and served: confirm the vault
    /// directory's durability and re-import into the mirror. Both steps
    /// are idempotent, so this heals a prior post-rename `fsync` failure
    /// (including across a restart), a crash before the mirror
    /// write-through, or a concurrent winner this process never observed.
    /// Takes the already-computed root: rehashing here would pay a full
    /// pass over the representation on exactly the degraded path this
    /// queue exists to keep cheap.
    fn reconcile_held(&self, root: BaoRoot, sealed: &[u8]) -> Result<(), VaultError> {
        self.durability.verify_dir(&self.dir)?;
        self.notify_mirror(root, sealed)?;
        Ok(())
    }

    /// Write-through to the serving mirror. A detached channel only
    /// delays serving until the next boot rebuild, never the
    /// publication — but a poisoned slot lock fails the import, and a
    /// full bounded queue applies backpressure (`VaultError::MirrorFull`,
    /// naming the refused root): the vault file is already durable, so
    /// the caller retries the import on a later pass and the readiness
    /// barrier stays not-ready until the drain catches up. Poison means
    /// a thread panicked mid-critical-section, so the operation fails
    /// instead of the process.
    fn notify_mirror(&self, root: BaoRoot, sealed: &[u8]) -> Result<(), VaultError> {
        let sender = self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))?
            .clone();
        if let Some(sender) = sender {
            sender.send_import(root, sealed.to_vec())?;
        }
        Ok(())
    }

    /// Live queue observability, if a mirror is attached: `None` when
    /// serving is detached (shutdown or never opened).
    pub fn mirror_stats(&self) -> Option<MirrorStats> {
        self.mirror
            .lock()
            .ok()?
            .as_ref()
            .map(|sender| sender.stats())
    }

    /// Attach the write-through channel of a serving mirror. Replacing
    /// an already-attached channel strands the old one (its sends fail
    /// and are ignored); a serving restart is the normal replacement.
    pub(crate) fn attach_mirror(&self, sender: MirrorSender) -> Result<(), VaultError> {
        *self
            .mirror
            .lock()
            .map_err(|_| std::io::Error::other("vault mirror lock poisoned"))? = Some(sender);
        Ok(())
    }

    /// The sealed bytes at a transport root, if held — and the read is
    /// verified: filenames are mutable filesystem state, so a file whose
    /// contents no longer hash to its name is not the requested
    /// representation. A mismatch is absence (`None`), never bytes under
    /// the wrong root; the corrupt file is left in place for an explicit
    /// scrub path (reads never mutate append-only state).
    pub fn sealed(&self, root: &BaoRoot) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.path(root)) {
            Ok(bytes) => {
                if blob_root(&bytes) == *root {
                    Ok(Some(bytes))
                } else {
                    Ok(None)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Every transport root held. Unreferenced bytes are harmless
    /// (append-only CAS; GC does not exist in v0), and this iterator is
    /// how the composer reconciles vault residency against the records.
    pub fn roots(&self) -> Result<Vec<BaoRoot>, VaultError> {
        let mut roots = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(bytes) = hex_to_32(&name) {
                if entry.metadata()?.is_file() {
                    roots.push(BaoRoot::from_bytes(bytes));
                }
            }
        }
        roots.sort();
        Ok(roots)
    }

    fn path(&self, root: &BaoRoot) -> PathBuf {
        self.dir.join(root.to_string())
    }
}

fn hex_to_32(name: &str) -> Result<[u8; 32], ()> {
    if name.len() != 64 {
        return Err(());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in name.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).ok_or(())?;
        let lo = (chunk[1] as char).to_digit(16).ok_or(())?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}
