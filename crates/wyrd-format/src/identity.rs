//! Identity types. Two identity worlds, enforced by the type system:
//!
//! - `ContentId` — domain-separated BLAKE3 over *plaintext*; the logical
//!   world (trees, snapshots, local dedup). Drive members only.
//! - `StorageId` — domain-separated BLAKE3 over *ciphertext*; the physical
//!   world (vaults, fetch addresses). Safe for untrusted peers.
//! - `SnapshotId` — a `ContentId` of a snapshot object, its own type so the
//!   compiler can tell DAG references from file content.
//!
//! Never construct identifiers by hashing raw bytes with a bare hash call;
//! always go through the domain-separated derivations here. See
//! `docs/object-model.md` for the normative contract.

use std::fmt;

use thiserror::Error;

/// Width of every Wyrd identifier: DriveId, ContentId, StorageId,
/// SnapshotId alike. A format constant: encodings that embed identifiers
/// use this, never a literal. Kept crate-internal until a public consumer
/// needs it; literals in cross-crate test fixtures are fine.
pub(crate) const ID_LEN: usize = 32;

/// 32 bytes shared by every Wyrd identifier. Not constructible outside this
/// module; use the typed newtypes. Ordered bytewise.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RawId([u8; 32]);

/// Domain separation contexts, derived per object kind. Changing a context
/// string changes every identity derived with it — these are format constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Chunk,
    Tree,
    Snapshot,
    Manifest,
}

impl ObjectKind {
    /// The `derive_key` context for content identities of this kind.
    pub fn content_context(self) -> &'static str {
        match self {
            ObjectKind::Chunk => "wyrd content v1/chunk",
            ObjectKind::Tree => "wyrd content v1/tree",
            ObjectKind::Snapshot => "wyrd content v1/snapshot",
            ObjectKind::Manifest => "wyrd content v1/manifest",
        }
    }

    /// The envelope kind byte. Format constant (object-model.md):
    /// 0x00 chunk, 0x01 tree, 0x02 snapshot, 0x03 manifest.
    pub const fn byte(self) -> u8 {
        match self {
            ObjectKind::Chunk => 0x00,
            ObjectKind::Tree => 0x01,
            ObjectKind::Snapshot => 0x02,
            ObjectKind::Manifest => 0x03,
        }
    }

    /// The kind for an envelope kind byte, or `None` if unknown.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(ObjectKind::Chunk),
            0x01 => Some(ObjectKind::Tree),
            0x02 => Some(ObjectKind::Snapshot),
            0x03 => Some(ObjectKind::Manifest),
            _ => None,
        }
    }
}

macro_rules! define_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(RawId);

        impl $name {
            /// The raw 32 bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0 .0
            }

            /// Reconstruct from raw bytes. Callers must have obtained these
            /// bytes from a verified source; derivation is preferred.
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(RawId(bytes))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.as_bytes()))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, stringify!($name))?;
                write!(f, "({})", hex::encode(self.as_bytes()))
            }
        }
    };
}

define_id!(
    ContentId,
    "A plaintext-domain identity: the logical address of a chunk, tree, or
snapshot. Deterministic — identical content always yields the identical
Content ID. Drive members only; never exposed to vaults."
);
define_id!(
    StorageId,
    "A ciphertext-domain identity: the physical address of an encrypted
object. Deterministic over the ciphertext, which carries a fresh random
nonce, so equal plaintexts yield unrelated Storage IDs. Safe to expose to
vaults."
);
define_id!(
    SnapshotId,
    "The Content ID of a snapshot object — a node in the snapshot DAG,
distinct in type from ordinary file content."
);
define_id!(
    DriveId,
    "A random 256-bit identifier naming one logical drive. Never derived
from content, and never a Nostr identity: every identifier answers a
different question (DriveId: which drive? Nostr pubkey: which participant?
ContentId: which content? StorageId: which encrypted representation?).
Minting a drive (drawing the randomness) is a sync/owner concern; the
format layer only carries the identifier."
);
define_id!(
    DeviceId,
    "A Nostr x-only secp256k1 public key naming one device. Immutable for
the device's life: rotating means remove-and-readmit. Opaque 32 bytes at
the format layer; full BIP-340 key validation (lift_x) belongs to the
sync layer (trust.md, decision T11)."
);
define_id!(
    TransitionId,
    "The domain-separated BLAKE3 of a membership transition's signing
preimage concatenated with its signature. Stable because BIP-340 nonces
are deterministic. Distinct from ContentId by type: membership
transitions are sealed documents, not content-addressed objects."
);
define_id!(
    DeviceEncryptionKey,
    "The x-only secp256k1 public key used for capability-ECDH delivery of
epoch secrets (trust.md T14). Registered in the membership transition
that admits the device; owned as a secret only in the device's own
keystore. Distinct from DeviceId by type: the identity key signs, the
encryption key receives."
);
define_id!(
    BaoRoot,
    "The raw BLAKE3/Bao root of one stored representation — the address
verified streaming requests by. Routing metadata, never an identity: no
derivation connects it to ContentId or StorageId, and a wrong root only
fails a transfer, because identity is the AEAD tag plus content check on
arrival (object-model.md decision 26)."
);

impl ContentId {
    /// Derive the Content ID for plaintext of the given kind. The identity
    /// includes the object kind: a chunk and a tree can never collide.
    pub fn derive(kind: ObjectKind, plaintext: &[u8]) -> Self {
        Self(RawId(blake3::derive_key(kind.content_context(), plaintext)))
    }
}

impl StorageId {
    /// Derive the Storage ID for a ciphertext blob. The ciphertext must
    /// carry its own fresh random nonce; equality of Storage IDs implies
    /// equality of ciphertexts only.
    pub fn derive(ciphertext: &[u8]) -> Self {
        Self(RawId(blake3::derive_key("wyrd storage v1", ciphertext)))
    }
}

/// A collection length that does not fit the wire format's `u32` counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("length {0} exceeds the u32 wire count")]
pub(crate) struct CountOverflow(pub(crate) usize);

/// Narrow a collection length for the wire format. Lengths beyond
/// `u32::MAX` fail explicitly instead of truncating silently. Unreachable
/// with real inputs (a 4-billion-element vector is unallocatable), so
/// encoders assert the invariant loudly at the single place it could
/// break; the unit test pins the failure on synthetic lengths.
pub(crate) fn u32_len(len: usize) -> Result<u32, CountOverflow> {
    u32::try_from(len).map_err(|_| CountOverflow(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_id_is_deterministic_per_kind() {
        let a = ContentId::derive(ObjectKind::Chunk, b"hello");
        let b = ContentId::derive(ObjectKind::Chunk, b"hello");
        assert_eq!(a, b);
        let c = ContentId::derive(ObjectKind::Tree, b"hello");
        assert_ne!(a, c, "kinds must not collide");
        let d = ContentId::derive(ObjectKind::Chunk, b"hellp");
        assert_ne!(a, d);
    }

    #[test]
    fn storage_id_is_ciphertext_domain() {
        // Same plaintext encrypted twice (nonce variation simulated here by
        // distinct ciphertext inputs) must yield unrelated Storage IDs.
        let s1 = StorageId::derive(b"nonce-a||ciphertext");
        let s2 = StorageId::derive(b"nonce-b||ciphertext");
        assert_ne!(s1, s2);
    }

    #[test]
    fn id_types_are_distinct_at_rest() {
        let c = ContentId::derive(ObjectKind::Chunk, b"x");
        let s = StorageId::derive(b"x");
        // Same raw bytes would still be different types; this only checks
        // derivation contexts differ so cross-domain accidents are caught
        // by construction.
        assert_ne!(c.as_bytes(), s.as_bytes());
    }

    #[test]
    fn kind_bytes_round_trip() {
        for kind in [
            ObjectKind::Chunk,
            ObjectKind::Tree,
            ObjectKind::Snapshot,
            ObjectKind::Manifest,
        ] {
            assert_eq!(ObjectKind::from_byte(kind.byte()), Some(kind));
        }
        // Distinct, compact, ascending — the format constant table.
        assert_eq!(ObjectKind::Chunk.byte(), 0x00);
        assert_eq!(ObjectKind::Tree.byte(), 0x01);
        assert_eq!(ObjectKind::Snapshot.byte(), 0x02);
        assert_eq!(ObjectKind::Manifest.byte(), 0x03);
    }

    #[test]
    fn unknown_kind_bytes_are_rejected() {
        assert_eq!(ObjectKind::from_byte(0x04), None);
        assert_eq!(ObjectKind::from_byte(0xFF), None);
    }

    #[test]
    fn wire_lengths_reject_counts_beyond_u32() {
        assert_eq!(u32_len(0), Ok(0));
        assert_eq!(u32_len(u32::MAX as usize), Ok(u32::MAX));
        assert_eq!(
            u32_len(u32::MAX as usize + 1),
            Err(CountOverflow(u32::MAX as usize + 1))
        );
        assert!(u32_len(usize::MAX).is_err());
    }
}
