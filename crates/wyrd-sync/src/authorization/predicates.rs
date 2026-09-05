//! Snapshot signature verification over the pinned challenge (trust.md),
//! and the per-snapshot predicate inputs the engine consumes.

use secp256k1::schnorr::Signature;
use secp256k1::{XOnlyPublicKey, SECP256K1};
use wyrd_format::{DriveId, Snapshot};

/// BIP-340 challenge context for snapshots (trust.md).
pub const SNAPSHOT_CHALLENGE_CONTEXT: &str = "wyrd snapshot challenge v1";

/// The 32-byte BIP-340 challenge for a snapshot's signing message.
pub fn snapshot_challenge(s: &Snapshot, drive: &DriveId) -> [u8; 32] {
    blake3::derive_key(SNAPSHOT_CHALLENGE_CONTEXT, &s.signing_message(drive))
}

/// Whether the snapshot's signature verifies. Full key validation
/// (lift_x, exactly 64-byte signatures) is delegated to the audited
/// secp256k1 implementation; lift_x failure is reported distinctly so
/// the sender can be flagged for malformed author keys.
pub(crate) fn verify_snapshot(drive: &DriveId, s: &Snapshot) -> Result<(), super::Rejection> {
    let pk = XOnlyPublicKey::from_slice(s.author.as_bytes())
        .map_err(|_| super::Rejection::InvalidAuthorKey)?;
    let sig = Signature::from_slice(&s.signature).map_err(|_| super::Rejection::BadSignature)?;
    let challenge = snapshot_challenge(s, drive);
    SECP256K1
        .verify_schnorr(&sig, &challenge, &pk)
        .map_err(|_| super::Rejection::BadSignature)
}
