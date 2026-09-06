//! The Wyrd NIP-46 extension contract: `sign_message` (trust.md "NIP-46
//! remote signing").
//!
//! Standard NIP-46 `sign_event` signs Nostr events, not arbitrary
//! digests — it cannot produce Wyrd's signatures (BIP-340 over the pinned
//! Wyrd message digest). The daemon therefore requests exactly one
//! 32-byte digest plus the context string naming what it is (e.g. the
//! ASCII domain of the signing message); the scoped signer session
//! returns the 64-byte BIP-340 signature. `get_public_key` and
//! `sign_message` are the session's only methods — default-deny
//! (trust.md). Transport rides `nostr-connect`-style tooling, which is a
//! later issue; this module pins the request/response bytes.
//!
//! Canonical encoding (counted with `u32`, little-endian):
//!
//! ```text
//! Request:   context u32+UTF-8 bytes ‖ digest (32)
//! Response:  signature (64)
//! ```

use super::ControlError;

/// A `sign_message` request: the context naming the digest plus the
/// 32-byte pinned Wyrd message digest itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessageRequest {
    pub context: String,
    pub digest: [u8; 32],
}

/// A `sign_message` response: the BIP-340 signature over the digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignMessageResponse {
    pub signature: [u8; 64],
}

impl SignMessageRequest {
    /// The canonical request bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.context.len() + 32);
        out.extend_from_slice(&(self.context.len() as u32).to_le_bytes());
        out.extend_from_slice(self.context.as_bytes());
        out.extend_from_slice(&self.digest);
        out
    }

    /// Decode a request. Rejects truncation, trailing bytes, and
    /// non-UTF-8 contexts.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlError> {
        if bytes.len() < 4 {
            return Err(ControlError::Truncated);
        }
        let n = u32::from_le_bytes(bytes[0..4].try_into().expect("bounds checked")) as usize;
        if bytes.len() < 4 + n + 32 {
            return Err(ControlError::Truncated);
        }
        let context =
            String::from_utf8(bytes[4..4 + n].to_vec()).map_err(|_| ControlError::BadContext)?;
        let digest = bytes[4 + n..4 + n + 32].try_into().expect("bounds checked");
        if bytes.len() != 4 + n + 32 {
            return Err(ControlError::TrailingBytes);
        }
        Ok(SignMessageRequest { context, digest })
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
            context: "wyrd membership v1".to_string(),
            digest: [0x42; 32],
        }
    }

    #[test]
    fn request_round_trips_context_and_digest() {
        let bytes = request().encode();
        assert_eq!(SignMessageRequest::decode(&bytes).unwrap(), request());
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

    #[test]
    fn request_rejects_truncated_trailing_and_non_utf8() {
        let bytes = request().encode();
        assert_eq!(
            SignMessageRequest::decode(&bytes[..5]),
            Err(ControlError::Truncated)
        );
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert_eq!(
            SignMessageRequest::decode(&trailing),
            Err(ControlError::TrailingBytes)
        );
        // Declared context longer than the buffer.
        let mut lying = bytes.clone();
        lying[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            SignMessageRequest::decode(&lying),
            Err(ControlError::Truncated)
        );
        // Non-UTF-8 context bytes.
        let mut bad = request().encode();
        bad[4] = 0xFF;
        assert_eq!(
            SignMessageRequest::decode(&bad),
            Err(ControlError::BadContext)
        );
    }
}
