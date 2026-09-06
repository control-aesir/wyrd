//! Sealed objects and manifest-entry verification (object-model.md
//! decisions 9 and 15; trust.md "AEAD binding").
//!
//! The physical world: every object a vault stores is an
//! [`EncryptedObject`] — `version ‖ kind ‖ nonce ‖ ciphertext` — sealed
//! with XChaCha20-Poly1305 under a per-epoch key, with the AAD binding
//! `(version, kind, ContentId)` exactly as trust.md pins it. The
//! [`StorageId`] is derived over the sealed bytes, so equal plaintexts
//! sealed twice (fresh nonces) yield unrelated StorageIds and the sealed
//! bytes carry no ContentId and no paths.
//!
//! Which key seals what is the caller's choice from the epoch hierarchy
//! (`keys::epoch`): content objects (chunks, trees) seal under
//! [`EpochSecret::object_key`], whole manifests under
//! [`EpochSecret::manifest_key`] (one key per snapshot — all subtree
//! manifests of a snapshot share it; per-entry epochs still allow
//! mixed-epoch mappings, which is how dedup survives rotation).
//!
//! Acting on a manifest mapping requires [`verify`]: envelope form,
//! header agreement with the entry, StorageId agreement, the AEAD tag
//! over the bound AAD, *and* the plaintext hashing to the ContentId. The
//! key must be the entry's epoch key (held via the device keyring): any
//! other epoch's key fails the tag, so cross-epoch reuse without the
//! matching capability is impossible here, not merely discouraged.
//!
//! [`EpochSecret::object_key`]: crate::keys::EpochSecret::object_key
//! [`EpochSecret::manifest_key`]: crate::keys::EpochSecret::manifest_key

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use thiserror::Error;
use wyrd_format::{ContentId, Manifest, ManifestEntry, ManifestError, ObjectKind, StorageId};

use crate::keys::{random_bytes, CryptoError};

/// The only sealed-envelope version. Bumping it is a format change with
/// new derived-key contexts, never a runtime branch.
pub const SEAL_VERSION: u8 = 0x00;

/// Header length: version (1) + kind (1) + nonce (24).
pub const SEAL_HEADER_LEN: usize = 26;

/// AEAD tag length for XChaCha20-Poly1305: anything shorter cannot be a
/// seal this module produced.
pub const SEAL_TAG_LEN: usize = 16;

/// A sealed, vault-storable object. Opaque by construction: no ContentId,
/// no paths, no structure — only version, kind, nonce, and ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedObject {
    pub version: u8,
    pub kind: ObjectKind,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Opening a sealed manifest fails either in crypto or in manifest
/// structure: a decrypted-but-unparsable manifest is corrupt evidence,
/// not a crypto failure, and the caller learns which.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealError {
    #[error("sealed-object crypto failed")]
    Crypto(#[from] CryptoError),
    #[error("decrypted bytes are not a canonical manifest")]
    Manifest(#[from] ManifestError),
}

impl EncryptedObject {
    /// The canonical sealed bytes: `version ‖ kind ‖ nonce ‖ ciphertext`.
    /// [`storage_id`] is defined over exactly these bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEAL_HEADER_LEN + self.ciphertext.len());
        out.push(self.version);
        out.push(self.kind.byte());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse sealed bytes. Rejects truncation (a tag without room for a
    /// header is not something [`seal`] produced) and unknown kinds.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() < SEAL_HEADER_LEN + SEAL_TAG_LEN {
            return Err(CryptoError::Malformed);
        }
        let kind = ObjectKind::from_byte(bytes[1]).ok_or(CryptoError::Malformed)?;
        Ok(EncryptedObject {
            version: bytes[0],
            kind,
            nonce: bytes[2..26].try_into().expect("bounds checked"),
            ciphertext: bytes[26..].to_vec(),
        })
    }

    /// The vault-visible address of this representation: defined over the
    /// sealed bytes, so re-sealing the same content yields an unrelated
    /// address (fresh nonce) and equal plaintexts stay unlinkable.
    pub fn storage_id(&self) -> StorageId {
        StorageId::derive(&self.encode())
    }
}

/// The pinned AAD (trust.md "AEAD binding"): `version ‖ kind ‖ ContentId`.
fn seal_aad(version: u8, kind: ObjectKind, content_id: &ContentId) -> [u8; 34] {
    let mut aad = [0u8; 34];
    aad[0] = version;
    aad[1] = kind.byte();
    aad[2..34].copy_from_slice(content_id.as_bytes());
    aad
}

/// Seal plaintext under a per-epoch key. Fails closed when the named
/// content is not this plaintext: an envelope whose AAD names foreign
/// content must never exist, even transiently.
pub fn seal(
    key: &[u8; 32],
    kind: ObjectKind,
    content_id: &ContentId,
    plaintext: &[u8],
) -> Result<EncryptedObject, CryptoError> {
    if ContentId::derive(kind, plaintext) != *content_id {
        return Err(CryptoError::IdentityMismatch);
    }
    let mut nonce = [0u8; 24];
    random_bytes(&mut nonce)?;
    let aad = seal_aad(SEAL_VERSION, kind, content_id);
    let ciphertext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
        .encrypt(
            chacha20poly1305::XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::RngFailed)?;
    Ok(EncryptedObject {
        version: SEAL_VERSION,
        kind,
        nonce,
        ciphertext,
    })
}

/// Open a sealed object: the version must be current, the AEAD tag must
/// verify over the AAD naming `expected`, *and* the plaintext must hash
/// to `expected`. Either check catches a mismatched mapping on its own;
/// both are required.
pub fn open(
    key: &[u8; 32],
    expected: &ContentId,
    obj: &EncryptedObject,
) -> Result<Vec<u8>, CryptoError> {
    if obj.version != SEAL_VERSION {
        return Err(CryptoError::Malformed);
    }
    let aad = seal_aad(obj.version, obj.kind, expected);
    let plaintext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key))
        .decrypt(
            chacha20poly1305::XNonce::from_slice(&obj.nonce),
            Payload {
                msg: &obj.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::OpenFailed)?;
    if ContentId::derive(obj.kind, &plaintext) != *expected {
        return Err(CryptoError::IdentityMismatch);
    }
    Ok(plaintext)
}

/// Seal a whole manifest under a snapshot manifest key. Returns the
/// manifest's logical identity (member-only) alongside the sealed object
/// (vault-visible): the ContentId names *what*, the StorageId names
/// *which sealed representation*.
pub fn seal_manifest(
    manifest_key: &[u8; 32],
    manifest: &Manifest,
) -> Result<(ContentId, EncryptedObject), CryptoError> {
    let plaintext = manifest.canonical_bytes();
    let content_id = ContentId::derive(ObjectKind::Manifest, &plaintext);
    let obj = seal(manifest_key, ObjectKind::Manifest, &content_id, &plaintext)?;
    Ok((content_id, obj))
}

/// Open a sealed manifest: crypto first, then canonical structure. A
/// well-tagged but unparsable document is corrupt evidence.
pub fn open_manifest(
    manifest_key: &[u8; 32],
    expected: &ContentId,
    obj: &EncryptedObject,
) -> Result<Manifest, SealError> {
    if obj.kind != ObjectKind::Manifest {
        return Err(SealError::Crypto(CryptoError::HeaderMismatch));
    }
    let plaintext = open(manifest_key, expected, obj)?;
    Ok(Manifest::from_canonical_bytes(&plaintext)?)
}

/// Enforce a manifest mapping end to end: envelope form, header and
/// StorageId agreement with the entry, the AEAD tag over the bound AAD,
/// the plaintext hashing to the entry's ContentId, and the opened size
/// matching the entry. Returns the verified plaintext.
pub fn verify(
    entry: &ManifestEntry,
    epoch_key: &[u8; 32],
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let obj = EncryptedObject::decode(sealed)?;
    if obj.version != entry.version || obj.kind != entry.kind {
        return Err(CryptoError::HeaderMismatch);
    }
    if obj.storage_id() != entry.storage_id {
        return Err(CryptoError::HeaderMismatch);
    }
    let plaintext = open(epoch_key, &entry.content_id, &obj)?;
    if plaintext.len() as u64 != entry.size {
        return Err(CryptoError::HeaderMismatch);
    }
    Ok(plaintext)
}

/// Build the entry for freshly sealed content: the caller seals under
/// the current epoch and records where and how the representation lives.
/// The returned entry always verifies under the same key.
pub fn entry_for(
    kind: ObjectKind,
    version: u8,
    epoch: u64,
    obj: &EncryptedObject,
    content_id: &ContentId,
    size: u64,
) -> Result<ManifestEntry, CryptoError> {
    if version != SEAL_VERSION {
        return Err(CryptoError::HeaderMismatch);
    }
    if obj.version != version || obj.kind != kind {
        return Err(CryptoError::HeaderMismatch);
    }
    Ok(ManifestEntry {
        content_id: *content_id,
        kind,
        version,
        storage_id: obj.storage_id(),
        encryption_epoch: epoch,
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::EpochSecret;
    use wyrd_format::{DriveId, SnapshotId};

    fn drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn object_key() -> [u8; 32] {
        let secret = EpochSecret::from_bytes([0x01; 32]);
        let content = ContentId::from_bytes([0x02; 32]);
        secret.object_key(&drive(), 1, &content, ObjectKind::Chunk, SEAL_VERSION)
    }

    fn chunk_fixture() -> (ContentId, Vec<u8>) {
        let plaintext = b"hello, vaults learn nothing".to_vec();
        let id = ContentId::derive(ObjectKind::Chunk, &plaintext);
        (id, plaintext)
    }

    #[test]
    fn seal_open_round_trips() {
        let (id, plaintext) = chunk_fixture();
        let obj = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        assert_eq!(open(&object_key(), &id, &obj).unwrap(), plaintext);
    }

    #[test]
    fn seal_refuses_a_foreign_content_id() {
        // Fail closed at seal time: the AAD must name this plaintext.
        let (_, plaintext) = chunk_fixture();
        let foreign = ContentId::from_bytes([0xFF; 32]);
        assert_eq!(
            seal(&object_key(), ObjectKind::Chunk, &foreign, &plaintext),
            Err(CryptoError::IdentityMismatch)
        );
    }

    #[test]
    fn open_with_the_wrong_key_fails_the_tag() {
        let (id, plaintext) = chunk_fixture();
        let obj = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        assert_eq!(open(&[0x99; 32], &id, &obj), Err(CryptoError::OpenFailed));
    }

    #[test]
    fn open_with_the_wrong_content_id_fails_the_tag() {
        let (id, plaintext) = chunk_fixture();
        let obj = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        let other = ContentId::from_bytes([0xAB; 32]);
        assert_eq!(
            open(&object_key(), &other, &obj),
            Err(CryptoError::OpenFailed)
        );
    }

    #[test]
    fn the_second_check_catches_a_hand_crafted_mismatch() {
        // open's hash check is defense in depth: craft an envelope whose
        // tag verifies over AAD(Q) but whose plaintext is P, bypassing
        // seal (which would have refused). The tag passes; the hash must
        // still fail.
        let key = object_key();
        let q = ContentId::from_bytes([0x51; 32]);
        let plaintext = b"plaintext that is not Q".to_vec();
        let mut nonce = [0u8; 24];
        random_bytes(&mut nonce).unwrap();
        let aad = seal_aad(SEAL_VERSION, ObjectKind::Chunk, &q);
        let ciphertext = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&key))
            .encrypt(
                chacha20poly1305::XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .unwrap();
        let obj = EncryptedObject {
            version: SEAL_VERSION,
            kind: ObjectKind::Chunk,
            nonce,
            ciphertext,
        };
        assert_eq!(open(&key, &q, &obj), Err(CryptoError::IdentityMismatch));
    }

    #[test]
    fn sealed_bytes_leak_neither_content_nor_structure() {
        // The vault-privacy property: the sealed form carries no ContentId
        // and no plaintext substring.
        let (id, plaintext) = chunk_fixture();
        let obj = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        let sealed = obj.encode();
        assert!(
            sealed.windows(32).all(|w| w != id.as_bytes()),
            "no ContentId in the sealed bytes"
        );
        assert!(
            sealed
                .windows(plaintext.len())
                .all(|w| w != plaintext.as_slice()),
            "no plaintext in the sealed bytes"
        );
    }

    #[test]
    fn storage_ids_are_stable_per_seal_and_fresh_per_wrap() {
        let (id, plaintext) = chunk_fixture();
        let a = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        let b = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        assert_ne!(a.encode(), b.encode(), "fresh nonce per seal");
        assert_ne!(
            a.storage_id(),
            b.storage_id(),
            "equal plaintexts stay unlinkable"
        );
        assert_eq!(
            a.storage_id(),
            EncryptedObject::decode(&a.encode()).unwrap().storage_id(),
            "decode/encode stability"
        );
    }

    #[test]
    fn malformed_seals_are_rejected() {
        assert_eq!(
            EncryptedObject::decode(&[0x00; 10]),
            Err(CryptoError::Malformed)
        );
        let empty_id = ContentId::derive(ObjectKind::Chunk, b"");
        let mut obj = seal(&object_key(), ObjectKind::Chunk, &empty_id, b"")
            .map(|o| o.encode())
            .unwrap();
        // Empty plaintext seals (ciphertext is tag-only); truncating into
        // the tag is malformed, not a tag failure.
        obj.truncate(obj.len() - 1);
        assert_eq!(EncryptedObject::decode(&obj), Err(CryptoError::Malformed));
        let hi_id = ContentId::derive(ObjectKind::Chunk, b"hi");
        let mut bad_kind = seal(&object_key(), ObjectKind::Chunk, &hi_id, b"hi")
            .unwrap()
            .encode();
        bad_kind[1] = 0x09;
        assert_eq!(
            EncryptedObject::decode(&bad_kind),
            Err(CryptoError::Malformed)
        );
    }

    #[test]
    fn manifest_seals_under_the_snapshot_key() {
        let secret = EpochSecret::from_bytes([0x03; 32]);
        let snapshot = SnapshotId::from_bytes([0x77; 32]);
        let key = secret.manifest_key(&drive(), 2, &snapshot);
        let manifest = Manifest {
            snapshot,
            entries: Vec::new(),
            children: Vec::new(),
        };
        let (content_id, obj) = seal_manifest(&key, &manifest).unwrap();
        assert_eq!(obj.kind, ObjectKind::Manifest);
        assert_eq!(open_manifest(&key, &content_id, &obj).unwrap(), manifest);
        // The manifest kind travels the envelope: opening a manifest
        // envelope as content (or vice versa) is a header mismatch.
        let hi_id = ContentId::derive(ObjectKind::Chunk, b"hi");
        let chunk_key = EpochSecret::from_bytes([0x03; 32]).object_key(
            &drive(),
            2,
            &hi_id,
            ObjectKind::Chunk,
            SEAL_VERSION,
        );
        let chunk_obj = seal(&chunk_key, ObjectKind::Chunk, &hi_id, b"hi").unwrap();
        assert_eq!(
            open_manifest(&key, &content_id, &chunk_obj),
            Err(SealError::Crypto(CryptoError::HeaderMismatch))
        );
    }

    #[test]
    fn verify_enforces_the_whole_entry() {
        let secret = EpochSecret::from_bytes([0x05; 32]);
        let (id, plaintext) = chunk_fixture();
        let key = secret.object_key(&drive(), 3, &id, ObjectKind::Chunk, SEAL_VERSION);
        let obj = seal(&key, ObjectKind::Chunk, &id, &plaintext).unwrap();
        let entry = entry_for(
            ObjectKind::Chunk,
            SEAL_VERSION,
            3,
            &obj,
            &id,
            plaintext.len() as u64,
        )
        .unwrap();
        assert_eq!(verify(&entry, &key, &obj.encode()).unwrap(), plaintext);
        // Another epoch's key fails the tag: no capability, no content.
        let other_key = secret.object_key(&drive(), 4, &id, ObjectKind::Chunk, SEAL_VERSION);
        assert_eq!(
            verify(&entry, &other_key, &obj.encode()),
            Err(CryptoError::OpenFailed)
        );
        // A lying entry (wrong size, wrong storage) fails the header.
        let mut lying = entry.clone();
        lying.size += 1;
        assert_eq!(
            verify(&lying, &key, &obj.encode()),
            Err(CryptoError::HeaderMismatch)
        );
        let mut swapped = entry.clone();
        swapped.storage_id = StorageId::from_bytes([0x11; 32]);
        assert_eq!(
            verify(&swapped, &key, &obj.encode()),
            Err(CryptoError::HeaderMismatch)
        );
    }

    #[test]
    fn entry_for_refuses_a_mismatched_envelope() {
        let (id, plaintext) = chunk_fixture();
        let obj = seal(&object_key(), ObjectKind::Chunk, &id, &plaintext).unwrap();
        assert_eq!(
            entry_for(
                ObjectKind::Tree,
                SEAL_VERSION,
                1,
                &obj,
                &id,
                plaintext.len() as u64
            ),
            Err(CryptoError::HeaderMismatch)
        );
    }
}
