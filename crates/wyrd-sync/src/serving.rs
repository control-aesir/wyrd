//! The durable serving surface: sealed envelopes the device authored or
//! fetched, keyed by the transport root the mappings and announcements
//! name (object-model.md decision 26). Append-only like the object
//! store; importing a root that is already held is a no-op, and a
//! restart loses nothing — the bytes are the drive's own ciphertext on
//! disk.
//!
//! [`Vault`] stores raw representation bytes and answers by the address
//! the bytes themselves hash to: the transport root, the same value the
//! verified transfer checks. [`VaultSource`] layers the composer's
//! durable runtime state over the vault so the eager snapshot/root
//! addresses (`sync-and-peers.md` exchange) also serve: the maps are
//! rebuilt from records and bodies on every pass, so restart
//! rehydration is "rebuild from durable state", never "rehydrate bytes".

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use wyrd_format::{BaoRoot, ContentId, SnapshotId, StorageId};

use crate::bulk::{BulkError, BulkSource, SealedManifest};
use crate::runtime::RuntimeState;
use crate::seal::blob_root;

/// The vault directory inside a drive directory.
const VAULT_DIR: &str = "vault";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault is not this drive's directory")]
    #[allow(dead_code)]
    Root,
}

/// The drive's sealed representation store: one file per transport root,
/// named by the root's hex, written atomically and never rewritten.
pub struct Vault {
    dir: PathBuf,
}

impl Vault {
    /// Open (or create) the vault directory under a drive directory.
    pub fn open(drive_dir: &Path) -> Result<Self, VaultError> {
        let dir = drive_dir.join(VAULT_DIR);
        std::fs::create_dir_all(&dir)?;
        Ok(Vault { dir })
    }

    /// Import sealed bytes: the file name is the bytes' own transport
    /// root, so the address handed out is exactly what the transfer
    /// verifies against. Importing an already-held root is a no-op —
    /// objects are immutable and the store is append-only.
    pub fn import(&self, sealed: &[u8]) -> Result<BaoRoot, VaultError> {
        let root = blob_root(sealed);
        let path = self.path(&root);
        if path.exists() {
            return Ok(root);
        }
        let tmp = self
            .dir
            .join(format!(".tmp-{}-{}", root, std::process::id()));
        {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(sealed)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(root)
    }

    /// The sealed bytes at a transport root, if held.
    pub fn sealed(&self, root: &BaoRoot) -> Result<Option<Vec<u8>>, VaultError> {
        match std::fs::read(self.path(root)) {
            Ok(bytes) => Ok(Some(bytes)),
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

/// The serving view of one drive: the vault's sealed bytes plus the
/// composer's durable runtime state, so every address the fetch plane
/// knows how to name is servable. The maps are derived — never stored —
/// so a restart rebuilds them by replaying durable state, and vault
/// bytes outlive every process.
pub struct VaultSource {
    vault: Vault,
    /// Root manifests by snapshot: the eager exchange address.
    roots: BTreeMap<SnapshotId, (ContentId, BaoRoot)>,
    /// Snapshot bodies: the plaintext CAS objects whose content id is
    /// the snapshot id.
    bodies: BTreeMap<SnapshotId, Vec<u8>>,
    /// Sealed representation addresses: storage id to transport root.
    sealed: BTreeMap<StorageId, BaoRoot>,
}

impl VaultSource {
    /// Rebuild the serving maps from durable state: root manifests from
    /// the recorded records, storage addresses from every recorded
    /// mapping and child link, bodies from the recorded snapshot
    /// bodies. Only recorded state serves — an announcement or mapping
    /// the device has not durably accepted is not offered to peers.
    pub fn from_state(state: &RuntimeState, vault: &Vault) -> Result<Self, VaultError> {
        let mut roots = BTreeMap::new();
        let mut bodies = BTreeMap::new();
        let mut sealed = BTreeMap::new();
        for snapshot in state.recorded_snapshots() {
            if let Some(record) = state.root_manifest_record(&snapshot) {
                roots.insert(snapshot, (record.manifest_id, record.transport));
                sealed.insert(
                    record
                        .storage_ids
                        .iter()
                        .next()
                        .copied()
                        .expect("recorded records hold their envelope"),
                    record.transport,
                );
            }
            if let Some(body) = state.snapshot_body(&snapshot) {
                bodies.insert(snapshot, body.encode());
            }
        }
        for record in state.manifest_records() {
            for entry in &record.manifest.entries {
                sealed.insert(entry.storage_id, entry.transport);
            }
            for link in &record.manifest.children {
                sealed.insert(link.storage, link.transport);
            }
        }
        Ok(VaultSource {
            vault: Vault {
                dir: vault.dir.clone(),
            },
            roots,
            bodies,
            sealed,
        })
    }
}

impl BulkSource for VaultSource {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        let Some((content_id, transport)) = self.roots.get(snapshot) else {
            return Ok(None);
        };
        let sealed = self
            .vault
            .sealed(transport)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(SealedManifest {
            content_id: *content_id,
            sealed,
        }))
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(body) = self.bodies.get(snapshot).cloned() else {
            return Ok(None);
        };
        if body.len() > max {
            return Err(BulkError::Oversize {
                bytes: body.len(),
                max,
            });
        }
        Ok(Some(body))
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let Some(transport) = self.sealed.get(storage).copied() else {
            return Ok(None);
        };
        self.fetch_transport(&transport, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        let sealed = self
            .vault
            .sealed(root)
            .map_err(|error| BulkError::Transport(error.to_string()))?;
        let Some(sealed) = sealed else {
            return Ok(None);
        };
        if sealed.len() > max {
            return Err(BulkError::Oversize {
                bytes: sealed.len(),
                max,
            });
        }
        Ok(Some(sealed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EpochSecret;
    use crate::seal::seal_manifest;
    use wyrd_format::{DriveId, Manifest, SnapshotId};

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn vault() -> Vault {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wyrd-vault-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Vault::open(&dir).unwrap()
    }

    #[test]
    fn imports_are_noop_for_held_roots_and_serve_by_root() {
        let vault = vault();
        let sealed = vec![0x42u8; 40];
        let root = vault.import(&sealed).unwrap();
        assert_eq!(root, blob_root(&sealed));
        assert_eq!(vault.sealed(&root).unwrap(), Some(sealed.clone()));
        // Re-import is a no-op (append-only; put of existing content).
        assert_eq!(vault.import(&sealed).unwrap(), root);
        // An unknown root is absence, not error.
        assert_eq!(
            vault.sealed(&BaoRoot::from_bytes([0x11; 32])).unwrap(),
            None
        );
        // The temp-file pattern must not leak into the root listing.
        assert_eq!(vault.roots().unwrap(), vec![root]);
    }

    #[test]
    fn partial_imports_never_serve() {
        // A torn write leaves a temp file, not a servable root: the
        // rename is the publication point.
        let vault = vault();
        let dir = &vault.dir;
        let torn = dir.join(".tmp-orphan");
        std::fs::write(&torn, b"half written").unwrap();
        assert_eq!(
            vault.sealed(&BaoRoot::from_bytes([0x33; 32])).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_source_serves_recorded_state_only() {
        // from_state layers the durable records over the vault: a
        // snapshot with neither a recorded root manifest nor a recorded
        // body serves nothing, and every recorded address serves.
        let vault = vault();
        let state = RuntimeState::new(drive());
        let mut source = VaultSource::from_state(&state, &vault).unwrap();
        let snapshot = SnapshotId::from_bytes([0x01; 32]);
        assert_eq!(
            source.fetch_root_manifest(&snapshot, usize::MAX).unwrap(),
            None
        );
        assert_eq!(source.fetch_snapshot(&snapshot, usize::MAX).unwrap(), None);
        assert_eq!(
            source
                .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
                .unwrap(),
            None
        );
        assert_eq!(
            source
                .fetch_transport(&BaoRoot::from_bytes([0x03; 32]), usize::MAX)
                .unwrap(),
            None
        );

        // Record a root manifest, import the envelope, and the same
        // source serves the root-manifest route by snapshot id, by
        // transport root, and by storage id.
        let manifest = Manifest {
            snapshot,
            entries: Vec::new(),
            children: Vec::new(),
        };
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let key = secret.manifest_key(&drive(), 1, &snapshot);
        let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
        vault.import(&obj.encode()).unwrap();
        let mut runtime = RuntimeState::new(drive());
        runtime
            .record_manifest(crate::runtime::ManifestRecord {
                is_root: true,
                manifest_id,
                storage_ids: std::collections::BTreeSet::from([obj.storage_id()]),
                transport: crate::seal::transport_root(&obj),
                manifest,
            })
            .unwrap();
        let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
        let served = source
            .fetch_root_manifest(&snapshot, usize::MAX)
            .unwrap()
            .expect("the recorded root manifest serves");
        assert_eq!(served.content_id, manifest_id);
        assert_eq!(served.sealed, obj.encode());
        assert_eq!(
            source
                .fetch_transport(&crate::seal::transport_root(&obj), usize::MAX)
                .unwrap(),
            Some(obj.encode())
        );
        assert_eq!(
            source.fetch_sealed(&obj.storage_id(), usize::MAX).unwrap(),
            Some(obj.encode())
        );
    }
}
