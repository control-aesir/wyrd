//! The private on-disk capability plaintext encoding.

use super::Capability;
use crate::keys::epoch::EpochSecret;
use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId, TransitionId};
use zeroize::Zeroizing;

/// Encode a capability for sealed durable storage. This is the same
/// plaintext document used inside the transport envelope.
pub(crate) fn plaintext_bytes(capability: &Capability) -> Zeroizing<Vec<u8>> {
    let mut pt = Zeroizing::new(Vec::with_capacity(
        128 + 8 + 4 + 32 * capability.secrets.len(),
    ));
    pt.extend_from_slice(capability.drive.as_bytes());
    pt.extend_from_slice(capability.device.as_bytes());
    pt.extend_from_slice(capability.encryption_key.as_bytes());
    pt.extend_from_slice(capability.transition.as_bytes());
    pt.extend_from_slice(&capability.up_to_epoch().to_le_bytes());
    pt.extend_from_slice(&(capability.secrets.len() as u32).to_le_bytes());
    for secret in &capability.secrets {
        pt.extend_from_slice(secret.as_bytes());
    }
    pt
}

/// Decode and validate a sealed capability plaintext document.
pub(crate) fn parse_plaintext(pt: &[u8]) -> Option<Capability> {
    if pt.len() < 140 || !(pt.len() - 140).is_multiple_of(32) {
        return None;
    }
    let epoch = u64::from_le_bytes(pt[128..136].try_into().ok()?);
    let count = u32::from_le_bytes(pt[136..140].try_into().ok()?) as u64;
    if epoch != count || pt.len() != 140 + count as usize * 32 {
        return None;
    }
    let secrets = pt[140..]
        .chunks_exact(32)
        .map(|c| EpochSecret::from_bytes(c.try_into().expect("chunks_exact(32)")))
        .collect();
    Capability::new(
        DriveId::from_bytes(pt[0..32].try_into().ok()?),
        DeviceId::from_bytes(pt[32..64].try_into().ok()?),
        DeviceEncryptionKey::from_bytes(pt[64..96].try_into().ok()?),
        TransitionId::from_bytes(pt[96..128].try_into().ok()?),
        epoch,
        secrets,
    )
    .ok()
}
