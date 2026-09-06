//! The Wyrd NIP-46 extension contract: `sign_message` (trust.md "NIP-46
//! remote signing").
//!
//! Standard NIP-46 `sign_event` signs Nostr events, not arbitrary
//! digests, so it cannot produce Wyrd's signatures (BIP-340 over the
//! pinned Wyrd message digest). The daemon instead requests a signature
//! over exactly one 32-byte digest within an explicit operation domain;
//! the scoped signer session returns the 64-byte BIP-340 signature. The
//! domain is a closed enum, never free text: a compromised client cannot
//! talk the signer into blessing an arbitrary digest under a permissive
//! label, because the signer authorizes per domain. `get_public_key` and
//! `sign_message` are the session's only methods (default-deny,
//! trust.md). Transport rides `nostr-connect`-style tooling, which is a
//! later issue; this module pins the request/response bytes.
//!
//! Canonical encoding (fixed-width):
//!
//! ```text
//! Request:   domain (1) ‖ drive (32) ‖ digest (32)
//! Response:  signature (64)
//! ```

use wyrd_format::DriveId;

use super::ControlError;

/// The operations a Wyrd signer session may be asked to sign. Closed:
/// adding an operation is a contract change, not a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignDomain {
    MembershipTransitionV1,
    SnapshotV1,
}

impl SignDomain {
    /// The canonical domain byte.
    pub fn byte(self) -> u8 {
        match self {
            SignDomain::MembershipTransitionV1 => 0x00,
            SignDomain::SnapshotV1 => 0x01,
        }
    }

    /// The domain for a byte, or `None` if unknown.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(SignDomain::MembershipTransitionV1),
            0x01 => Some(SignDomain::SnapshotV1),
            _ => None,
        }
    }
}

/// A `sign_message` request: the operation domain, the drive it belongs
/// to, and the 32-byte pinned Wyrd message digest itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessageRequest {
    pub domain: SignDomain,
    pub drive: DriveId,
    pub digest: [u8; 32],
}

/// A `sign_message` response: the BIP-340 signature over the digest.
/// Callers verify it against the expected signer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessageResponse {
    pub signature: [u8; 64],
}

impl SignMessageRequest {
    /// The canonical request bytes: fixed 65 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(self.domain.byte());
        out.extend_from_slice(self.drive.as_bytes());
        out.extend_from_slice(&self.digest);
        out
    }

    /// Decode a request. Fixed length with a closed domain byte: rejects
    /// truncation, trailing bytes, and unknown domains.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() < 65 {
            return Err(ControlError::Truncated);
        }
        if bytes.len() != 65 {
            return Err(ControlError::TrailingBytes);
        }
        let domain =
            SignDomain::from_byte(bytes[0]).ok_or(ControlError::UnknownSignDomain(bytes[0]))?;
        Ok(SignMessageRequest {
            domain,
            drive: DriveId::from_bytes(bytes[1..33].try_into().expect("bounds checked")),
            digest: bytes[33..65].try_into().expect("bounds checked"),
        })
    }
}

impl SignMessageResponse {
    /// The canonical response bytes: the 64-byte signature.
    pub fn encode(&self) -> Vec<u8> {
        self.signature.to_vec()
    }

    /// Decode a response. Exactly 64 bytes, nothing else.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() < 64 {
            return Err(ControlError::Truncated);
        }
        if bytes.len() != 64 {
            return Err(ControlError::TrailingBytes);
        }
        Ok(SignMessageResponse {
            signature: bytes[..64].try_into().expect("bounds checked"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> SignMessageRequest {
        SignMessageRequest {
            domain: SignDomain::MembershipTransitionV1,
            drive: DriveId::from_bytes([0xEE; 32]),
            digest: [0x42; 32],
        }
    }

    #[test]
    fn domains_are_closed_and_distinct() {
        assert_eq!(SignDomain::MembershipTransitionV1.byte(), 0x00);
        assert_eq!(SignDomain::SnapshotV1.byte(), 0x01);
        assert_eq!(SignDomain::from_byte(0x01), Some(SignDomain::SnapshotV1));
        assert_eq!(SignDomain::from_byte(0x02), None);
    }

    #[test]
    fn request_is_fixed_65_bytes() {
        let bytes = request().encode();
        assert_eq!(bytes.len(), 65);
        assert_eq!(SignMessageRequest::decode(&bytes).unwrap(), request());
    }

    #[test]
    fn request_rejects_truncated_trailing_and_unknown_domain() {
        let bytes = request().encode();
        assert_eq!(
            SignMessageRequest::decode(&bytes[..10]),
            Err(ControlError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            SignMessageRequest::decode(&trailing),
            Err(ControlError::TrailingBytes)
        );
        let mut unknown = bytes.clone();
        unknown[0] = 0x09;
        assert_eq!(
            SignMessageRequest::decode(&unknown),
            Err(ControlError::UnknownSignDomain(0x09))
        );
    }

    #[test]
    fn response_is_exactly_64_bytes() {
        let response = SignMessageResponse {
            signature: [0x55; 64],
        };
        assert_eq!(response.encode().len(), 64);
        assert_eq!(
            SignMessageResponse::decode(&response.encode()).unwrap(),
            response
        );
        assert_eq!(
            SignMessageResponse::decode(&[0x55; 63]),
            Err(ControlError::Truncated)
        );
        assert_eq!(
            SignMessageResponse::decode(&[0x55; 65]),
            Err(ControlError::TrailingBytes)
        );
    }
}
