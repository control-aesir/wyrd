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

/// A raw byte CAS with no authorization semantics: it stores and serves
/// bytes under their own hash, for whoever is allowed to reach the
/// drive's ciphertext at all. Authorization lives one layer up —
/// [`VaultSource`] offers only representations durably recorded by the
/// runtime machines, and every fetch still passes the AEAD/identity
/// admission checks before plaintext is trusted.
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
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
    /// objects are immutable and the store is append-only. The temp file
    /// is scoped to the root (distinct roots never collide on the temp
    /// path), and the rename is the publication point: a torn write
    /// leaves a temp file, never a servable root.
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

/// The serving view of one drive: the vault's sealed bytes plus the
/// composer's durable runtime state, so every address the fetch plane
/// knows how to name is servable. The maps are derived — never stored —
/// so a restart rebuilds them by replaying durable state, and vault
/// bytes outlive every process.
///
/// The verification chain stays three-staged (trust.md): the author's
/// signature proves the author named `R` as the route for identity `X`;
/// the transport (Bao/vault) proves received bytes hash to `R`; the
/// AEAD/content admission proves the received representation decrypts to
/// the claimed plaintext. This view participates in the first two — it
/// never substitutes for the third.
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
            // The root manifest serves by snapshot id and by the transport
            // root the record carries; a record with no sealed envelope
            // (recordable via the durable codec) still serves those two
            // routes, and contributes nothing to the storage map.
            if let Some(record) = state.root_manifest_record(&snapshot) {
                roots.insert(snapshot, (record.manifest_id, record.transport));
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
    fn corrupt_file_contents_serve_nothing_under_their_name() {
        // Filenames are mutable filesystem state: a file whose contents
        // no longer hash to its name is not the requested representation.
        // The read refuses (absence) and never mutates the append-only
        // store.
        let vault = vault();
        let sealed = vec![0x42u8; 40];
        let root = vault.import(&sealed).unwrap();
        std::fs::write(vault.dir.join(root.to_string()), b"tampered bytes").unwrap();
        assert_eq!(
            vault.sealed(&root).unwrap(),
            None,
            "bytes that do not hash to the requested root are absence"
        );
        assert_eq!(
            vault.roots().unwrap(),
            vec![root],
            "reads never mutate vault state; scrub is explicit"
        );
    }

    #[test]
    fn distinct_roots_never_collide_on_the_temp_path() {
        // The temp file is scoped to the root, so concurrent imports of
        // different roots through one vault cannot overwrite each other.
        let vault = vault();
        let a = vault.import(b"first representation").unwrap();
        let b = vault.import(b"second representation").unwrap();
        assert_ne!(a, b);
        assert_eq!(
            vault.sealed(&a).unwrap(),
            Some(b"first representation".to_vec())
        );
        assert_eq!(
            vault.sealed(&b).unwrap(),
            Some(b"second representation".to_vec())
        );
    }

    #[test]
    fn a_representationless_root_record_is_not_a_panic() {
        // Durable state can carry a root manifest with no sealed
        // representation at all (the codec accepts a zero storage count):
        // the serving view fails closed to "nothing to serve", never
        // panics at reconstruction.
        let vault = vault();
        let snapshot = SnapshotId::from_bytes([0x01; 32]);
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let manifest = Manifest {
            snapshot,
            entries: Vec::new(),
            children: Vec::new(),
        };
        let key = secret.manifest_key(&drive(), 1, &snapshot);
        let (manifest_id, obj) = seal_manifest(&key, &manifest).unwrap();
        vault.import(&obj.encode()).unwrap();
        let mut runtime = RuntimeState::new(drive());
        runtime
            .record_manifest(crate::runtime::ManifestRecord {
                is_root: true,
                manifest_id,
                storage_ids: std::collections::BTreeSet::new(),
                transport: crate::seal::transport_root(&obj),
                manifest,
            })
            .unwrap();
        let mut source = VaultSource::from_state(&runtime, &vault).unwrap();
        let served = source
            .fetch_root_manifest(&snapshot, usize::MAX)
            .unwrap()
            .expect("the root manifest still serves by id and root");
        assert_eq!(served.content_id, manifest_id);
        assert_eq!(
            source
                .fetch_sealed(&StorageId::from_bytes([0x02; 32]), usize::MAX)
                .unwrap(),
            None,
            "no storage representations were recorded, so none serve"
        );
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

        // Record a root manifest whose mapping names a sealed chunk, import
        // both envelopes, and the source serves the root-manifest routes
        // (by snapshot id and transport root) plus the mapped chunk by
        // its storage address.
        let secret = EpochSecret::from_bytes([0x07; 32]);
        let plaintext = b"vault served chunk".to_vec();
        let content = wyrd_format::ContentId::derive(wyrd_format::ObjectKind::Chunk, &plaintext);
        let chunk_key = secret.object_key(
            &drive(),
            1,
            &content,
            wyrd_format::ObjectKind::Chunk,
            crate::seal::SEAL_VERSION,
        );
        let sealed_chunk = crate::seal::seal(
            &chunk_key,
            wyrd_format::ObjectKind::Chunk,
            &content,
            &plaintext,
        )
        .unwrap();
        let entry = crate::seal::entry_for(
            wyrd_format::ObjectKind::Chunk,
            1,
            &sealed_chunk,
            &content,
            &plaintext,
        )
        .unwrap();
        vault.import(&sealed_chunk.encode()).unwrap();
        let manifest = Manifest {
            snapshot,
            entries: vec![entry],
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
            source
                .fetch_sealed(&sealed_chunk.storage_id(), usize::MAX)
                .unwrap(),
            Some(sealed_chunk.encode())
        );
    }
}
