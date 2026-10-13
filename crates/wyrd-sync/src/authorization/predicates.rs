//! Snapshot signature verification over the pinned challenge (trust.md),
//! and the per-snapshot predicate inputs the engine consumes.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use wyrd_format::signing::snapshot_challenge_for;
use wyrd_format::{DriveId, Snapshot};

/// Sign a snapshot in place with canonical BIP-340 nonces (trust.md,
/// "Exact signing construction"). Authors sign their own bodies; the
/// authoring path is the only production caller.
pub(crate) fn sign_snapshot(s: &mut Snapshot, sk: &SecretKey, drive: &DriveId) {
    let keypair = Keypair::from_secret_key(SECP256K1, sk);
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&snapshot_challenge_for(s, drive), &keypair);
    s.signature = sig.to_byte_array();
}

/// Whether the snapshot's signature verifies. Full key validation
/// (lift_x, exactly 64-byte signatures) is delegated to the audited
/// secp256k1 implementation; lift_x failure is reported distinctly so
/// the sender can be flagged for malformed author keys.
pub(crate) fn verify_snapshot(drive: &DriveId, s: &Snapshot) -> Result<(), super::Rejection> {
    let pk = XOnlyPublicKey::from_slice(s.author.as_bytes())
        .map_err(|_| super::Rejection::InvalidAuthorKey)?;
    let sig = Signature::from_slice(&s.signature).map_err(|_| super::Rejection::BadSignature)?;
    let challenge = snapshot_challenge_for(s, drive);
    SECP256K1
        .verify_schnorr(&sig, &challenge, &pk)
        .map_err(|_| super::Rejection::BadSignature)
}
