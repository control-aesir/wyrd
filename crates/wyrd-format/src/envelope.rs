//! The canonical object envelope (see `docs/object-model.md`,
//! "Canonical encoding"). Every object is a typed envelope and identity is
//! defined over exactly these bytes, so the framing must stay byte-exact
//! and inflexible:
//!
//! ```text
//! offset  size  field
//! 0       4     magic   = "wyrd"
//! 4       1     version = 0x00 (v0)
//! 5       1     kind    = 0x00 chunk | 0x01 tree | 0x02 snapshot
//! 6       ..    payload (kind-specific, canonical)
//! ```
//!
//! The version byte is validated, not stored: changing it means a new
//! format with new derived-key contexts, which is a new type, not a field
//! value. Payload canonicality (counted vectors etc.) is owned by the
//! kind-specific decoders; this layer only guarantees the framing.

use crate::identity::ObjectKind;
use thiserror::Error;

/// Envelope magic bytes.
pub const MAGIC: [u8; 4] = *b"wyrd";

/// The only accepted envelope version. Bumping it is a format change with
/// new derived-key contexts, never a runtime branch on this value.
pub const VERSION: u8 = 0x00;

/// magic (4) + version (1) + kind (1).
pub const HEADER_LEN: usize = 6;

/// A decoded object envelope. `payload` holds the kind-specific canonical
/// content; parsing it is the responsibility of the kind's own module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: ObjectKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EnvelopeError {
    #[error("input shorter than the {HEADER_LEN}-byte envelope header")]
    Truncated,
    #[error("bad magic: expected \"wyrd\"")]
    BadMagic,
    #[error("unknown envelope version {0:#04x}")]
    UnknownVersion(u8),
    #[error("unknown kind byte {0:#04x}")]
    UnknownKind(u8),
}

impl Envelope {
    /// The canonical byte encoding. The output is exactly
    /// `MAGIC ‖ VERSION ‖ kind ‖ payload`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind.byte());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse an envelope from its canonical encoding. Rejects short inputs,
    /// wrong magic, unsupported versions, and unknown kinds. Never accepts
    /// a version other than [`VERSION`] — newer formats arrive as additive
    /// representations (or snapshot-producing migrations), never as
    /// in-place rewrites; see `docs/upgrade-contract.md`.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() < HEADER_LEN {
            return Err(EnvelopeError::Truncated);
        }
        if bytes[..4] != MAGIC {
            return Err(EnvelopeError::BadMagic);
        }
        if bytes[4] != VERSION {
            return Err(EnvelopeError::UnknownVersion(bytes[4]));
        }
        let kind = ObjectKind::from_byte(bytes[5]).ok_or(EnvelopeError::UnknownKind(bytes[5]))?;
        Ok(Envelope {
            kind,
            payload: bytes[HEADER_LEN..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_chunk_golden_bytes() {
        // Hand-computed framing: "wyrd" (77 79 72 64), version 00, kind 00
        // (chunk), payload "hi" (68 69).
        let env = Envelope {
            kind: ObjectKind::Chunk,
            payload: b"hi".to_vec(),
        };
        assert_eq!(
            env.encode(),
            [0x77, 0x79, 0x72, 0x64, 0x00, 0x00, 0x68, 0x69]
        );
    }

    #[test]
    fn encode_kind_bytes_golden() {
        let payload = [0xAA];
        assert_eq!(
            Envelope {
                kind: ObjectKind::Chunk,
                payload: payload.into()
            }
            .encode()[5],
            0x00
        );
        assert_eq!(
            Envelope {
                kind: ObjectKind::Tree,
                payload: payload.into()
            }
            .encode()[5],
            0x01
        );
        assert_eq!(
            Envelope {
                kind: ObjectKind::Snapshot,
                payload: payload.into()
            }
            .encode()[5],
            0x02
        );
    }

    #[test]
    fn round_trips_every_kind() {
        for (kind, payload) in [
            (ObjectKind::Chunk, b"chunk bytes".to_vec()),
            (ObjectKind::Tree, vec![0x01, 0x02, 0x03]),
            (ObjectKind::Snapshot, vec![0xFF; 40]),
            (ObjectKind::Manifest, vec![0x07; 82]),
            (ObjectKind::Chunk, Vec::new()),
        ] {
            let env = Envelope {
                kind,
                payload: payload.clone(),
            };
            assert_eq!(Envelope::decode(&env.encode()).unwrap(), env);
        }
    }

    #[test]
    fn decode_rejects_truncated() {
        assert_eq!(Envelope::decode(&[]), Err(EnvelopeError::Truncated));
        assert_eq!(Envelope::decode(b"wyrd"), Err(EnvelopeError::Truncated));
        assert_eq!(Envelope::decode(b"wyrd\x00"), Err(EnvelopeError::Truncated));
    }

    #[test]
    fn decode_rejects_bad_magic() {
        assert_eq!(
            Envelope::decode(b"abcd\x00\x00rest"),
            Err(EnvelopeError::BadMagic)
        );
    }

    #[test]
    fn decode_rejects_unknown_version() {
        assert_eq!(
            Envelope::decode(b"wyrd\x01\x00rest"),
            Err(EnvelopeError::UnknownVersion(1))
        );
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        assert_eq!(
            Envelope::decode(b"wyrd\x00\x04rest"),
            Err(EnvelopeError::UnknownKind(4))
        );
    }

    #[test]
    fn identity_is_stable_across_encode_decode() {
        // The scrub invariant's foundation: the payload decoded from an
        // envelope derives the same ContentId as the payload that went in.
        let data = b"identity coherence";
        let env = Envelope {
            kind: ObjectKind::Chunk,
            payload: data.to_vec(),
        };
        let decoded = Envelope::decode(&env.encode()).unwrap();
        assert_eq!(
            crate::ContentId::derive(ObjectKind::Chunk, &decoded.payload),
            crate::ContentId::derive(ObjectKind::Chunk, data)
        );
    }
}
