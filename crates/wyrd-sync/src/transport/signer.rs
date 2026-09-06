//! The Wyrd NIP-46 signer session: the trait boundary a
//! `nostr-connect`-style session client implements for `sign_message`
//! (`control::nip46` pins the request/response bytes; `trust.md` "NIP-46
//! remote signing" pins the scoping rules).
//!
//! Real session negotiation (bunker URIs, relay handshake, connect/ack
//! events) is signer-client wiring, out of scope here for the same
//! reason as the mailbox's live relay pool (see `transport` module
//! doc): every test in this module runs against an in-memory fake
//! holding a real secp256k1 key, never a network.

use thiserror::Error;
use wyrd_format::DeviceId;

use crate::control::nip46::{SignMessageRequest, SignMessageResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignerError {
    #[error("signer session refused the request")]
    Refused,
    #[error("signer session is unreachable")]
    Unreachable,
}

/// A scoped Wyrd signer session: `get_public_key` and `sign_message`
/// only (default-deny, `trust.md`). A concrete session negotiates
/// `nostr-connect` transport underneath this trait.
pub trait SignerSession {
    /// The device identity this session signs for.
    fn get_public_key(&self) -> Result<DeviceId, SignerError>;

    /// Request a BIP-340 signature over one domain-scoped digest.
    fn sign_message(&self, request: SignMessageRequest)
        -> Result<SignMessageResponse, SignerError>;
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use crate::control::nip46::SignDomain;
    use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
    use std::collections::HashSet;

    /// An in-process signer holding a real secp256k1 key: a stand-in
    /// for the hardware/phone/bunker signer, scoped to an explicit
    /// allow-list of domains — default-deny means an empty allow-list
    /// refuses every request, matching the real session's posture.
    pub(crate) struct FakeSignerSession {
        keypair: Keypair,
        allowed: HashSet<SignDomain>,
    }

    impl FakeSignerSession {
        pub(crate) fn new(secret: &secp256k1::SecretKey, allowed: &[SignDomain]) -> Self {
            FakeSignerSession {
                keypair: Keypair::from_secret_key(SECP256K1, secret),
                allowed: allowed.iter().copied().collect(),
            }
        }
    }

    impl SignerSession for FakeSignerSession {
        fn get_public_key(&self) -> Result<DeviceId, SignerError> {
            let (xonly, _) = XOnlyPublicKey::from_keypair(&self.keypair);
            Ok(DeviceId::from_bytes(xonly.serialize()))
        }

        fn sign_message(
            &self,
            request: SignMessageRequest,
        ) -> Result<SignMessageResponse, SignerError> {
            if !self.allowed.contains(&request.domain) {
                return Err(SignerError::Refused);
            }
            let signature = SECP256K1
                .sign_schnorr_no_aux_rand(&request.digest, &self.keypair)
                .to_byte_array();
            Ok(SignMessageResponse { signature })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::FakeSignerSession;
    use super::*;
    use crate::control::nip46::SignDomain;
    use wyrd_format::DriveId;

    fn secret() -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[0x2A; 32]).unwrap()
    }

    fn request(domain: SignDomain) -> SignMessageRequest {
        SignMessageRequest {
            domain,
            drive: DriveId::from_bytes([0xEE; 32]),
            digest: [0x42; 32],
        }
    }

    #[test]
    fn allowed_domain_returns_a_verifiable_signature() {
        let session = FakeSignerSession::new(&secret(), &[SignDomain::SnapshotV1]);
        let response = session
            .sign_message(request(SignDomain::SnapshotV1))
            .unwrap();
        let sig = secp256k1::schnorr::Signature::from_slice(&response.signature).unwrap();
        use secp256k1::{Keypair, XOnlyPublicKey, SECP256K1};
        let kp = Keypair::from_secret_key(SECP256K1, &secret());
        let (pk, _) = XOnlyPublicKey::from_keypair(&kp);
        assert!(SECP256K1
            .verify_schnorr(&sig, &request(SignDomain::SnapshotV1).digest, &pk)
            .is_ok());
        assert_eq!(
            session.get_public_key().unwrap(),
            DeviceId::from_bytes(pk.serialize())
        );
    }

    #[test]
    fn default_deny_refuses_domains_outside_the_allow_list() {
        // Empty allow-list: every request is refused, matching the
        // real session's default-deny posture.
        let session = FakeSignerSession::new(&secret(), &[]);
        assert_eq!(
            session.sign_message(request(SignDomain::MembershipTransitionV1)),
            Err(SignerError::Refused)
        );

        // A session scoped to one domain refuses every other domain.
        let scoped = FakeSignerSession::new(&secret(), &[SignDomain::SnapshotV1]);
        assert_eq!(
            scoped.sign_message(request(SignDomain::MembershipTransitionV1)),
            Err(SignerError::Refused)
        );
    }
}
