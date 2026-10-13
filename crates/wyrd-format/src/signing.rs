//! The closed signing-domain enum and the BIP-340 challenge finalizations.
//!
//! A minimal remote signer recomputes Wyrd digests while depending only
//! on `wyrd-format` plus `secp256k1`/`blake3`: the domain enum, the
//! `derive_key` contexts, and the preimage-to-challenge finalizations
//! live here, so the signer never imports the transport. The signing
//! *sessions* (local key, fake, NIP-46 framing) stay in `wyrd-sync`:
//! this module owns what is signed, the sync layer owns how signing is
//! requested.
//!
//! Deliberately not here: the epoch-secret vector commitment and the
//! owner-proof preimage builder. Both touch sync-side key material
//! (`EpochSecret`) and `Zeroizing` buffers, neither of which belongs in
//! the plaintext format crate, and a clear-signing remote session
//! receives full preimages — it finalizes them with
//! [`owner_proof_challenge`], it never builds them.

use crate::{DriveId, MembershipTransition, Snapshot};

/// The operations a Wyrd signer session may be asked to sign. Closed:
/// adding an operation is a contract change, not a string.
///
/// The domain byte is a Wyrd-private allocation, not a Nostr registry
/// value: standard NIP-46 defines method names (`sign_event`, ...), never
/// signing domains, so there is no upstream value to reuse for the owner
/// proof — `0x02` continues the private sequence `0x00`/`0x01` above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignDomain {
    MembershipTransitionV1,
    SnapshotV1,
    OwnerProofV1,
}

impl SignDomain {
    /// The canonical domain byte.
    pub fn byte(self) -> u8 {
        match self {
            SignDomain::MembershipTransitionV1 => 0x00,
            SignDomain::SnapshotV1 => 0x01,
            SignDomain::OwnerProofV1 => 0x02,
        }
    }

    /// The domain for a byte, or `None` if unknown.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x00 => Some(SignDomain::MembershipTransitionV1),
            0x01 => Some(SignDomain::SnapshotV1),
            0x02 => Some(SignDomain::OwnerProofV1),
            _ => None,
        }
    }
}

/// BIP-340 challenge context for membership transitions (trust.md).
pub const CHALLENGE_CONTEXT: &str = "wyrd membership challenge v1";

/// BIP-340 challenge context for snapshots (trust.md).
pub const SNAPSHOT_CHALLENGE_CONTEXT: &str = "wyrd snapshot challenge v1";

/// Domain context for the owner-proof signed preimage (T12: every
/// derived constant agrees byte-for-byte across implementations).
pub const PROOF_CONTEXT: &str = "wyrd owner proof v1";

/// The 32-byte BIP-340 challenge for a membership signing preimage:
/// `BLAKE3-derive-key(CHALLENGE_CONTEXT, preimage)`. Callers pass
/// `MembershipTransition::signing_message(drive)`; the function takes
/// the preimage bytes so a remote signer, which receives preimages it
/// did not build, shares the exact finalization. Production callers
/// that hold the typed object should prefer
/// [`membership_challenge_for`], which keeps the compiler bound to the
/// signing message.
pub fn membership_challenge(preimage: &[u8]) -> [u8; 32] {
    blake3::derive_key(CHALLENGE_CONTEXT, preimage)
}

/// Type-bound form of [`membership_challenge`]: the hashed bytes are
/// always this transition's signing message, so a future caller cannot
/// park foreign bytes under the membership domain. The raw form stays
/// for the remote signer.
pub fn membership_challenge_for(t: &MembershipTransition, drive: &DriveId) -> [u8; 32] {
    membership_challenge(&t.signing_message(drive))
}

/// The 32-byte BIP-340 challenge for a snapshot signing preimage.
/// Same preimage-passing shape as [`membership_challenge`]; production
/// callers that hold the typed object should prefer
/// [`snapshot_challenge_for`].
pub fn snapshot_challenge(preimage: &[u8]) -> [u8; 32] {
    blake3::derive_key(SNAPSHOT_CHALLENGE_CONTEXT, preimage)
}

/// Type-bound form of [`snapshot_challenge`]: the hashed bytes are
/// always this snapshot's signing message. The raw form stays for the
/// remote signer.
pub fn snapshot_challenge_for(s: &Snapshot, drive: &DriveId) -> [u8; 32] {
    snapshot_challenge(&s.signing_message(drive))
}

/// The 32-byte BIP-340 challenge for an owner-proof preimage. Same
/// preimage-passing shape as [`membership_challenge`]: the secret-vector
/// commitment inside the preimage is computed sync-side, the signer
/// only finalizes. There is no type-bound form — the preimage builder
/// lives sync-side with the key material, so format cannot name it.
pub fn owner_proof_challenge(preimage: &[u8]) -> [u8; 32] {
    blake3::derive_key(PROOF_CONTEXT, preimage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Change, ContentId, DeviceId, TransitionId};

    #[test]
    fn domains_are_closed_and_distinct() {
        assert_eq!(SignDomain::MembershipTransitionV1.byte(), 0x00);
        assert_eq!(SignDomain::SnapshotV1.byte(), 0x01);
        assert_eq!(SignDomain::OwnerProofV1.byte(), 0x02);
        assert_eq!(SignDomain::from_byte(0x01), Some(SignDomain::SnapshotV1));
        assert_eq!(SignDomain::from_byte(0x02), Some(SignDomain::OwnerProofV1));
        assert_eq!(SignDomain::from_byte(0x03), None);
    }

    /// Each challenge binds its context string: a context edit, or a
    /// preimage/finalization swap between domains, breaks these rather
    /// than passing review. Inputs are fixed fixture bytes — the
    /// preimage-to-challenge wiring over real objects is pinned by the
    /// sync-side signature vectors.
    #[test]
    fn membership_challenge_matches_known_answer() {
        assert_eq!(
            hex::encode(membership_challenge(b"wyrd signing fixture: membership")),
            "90b5631c64857e487e85765241063a85aba6fd3a09ce4b19a3cd9c45c6822769"
        );
    }

    #[test]
    fn snapshot_challenge_matches_known_answer() {
        assert_eq!(
            hex::encode(snapshot_challenge(b"wyrd signing fixture: snapshot")),
            "d3003515855dd71710344c194aa5be12b241cebac6688356fba98c9a688a5f3f"
        );
    }

    #[test]
    fn owner_proof_challenge_matches_known_answer() {
        assert_eq!(
            hex::encode(owner_proof_challenge(b"wyrd signing fixture: owner proof")),
            "cdeedd5972d2cb206e3710ef577f847c654548e3c9a3884ad6dba1a7d057e481"
        );
    }

    /// The typed wrappers pin their own wiring, not just the raw
    /// finalization: these prove the hashed bytes are the object's
    /// `signing_message` for this drive. An edit that swapped in a
    /// different preimage (or a different drive binding) breaks these
    /// while leaving the raw-finalization pins above green, and the
    /// sync-side round trips would move sign and verify together —
    /// so without these, nothing in the tree would fail.
    fn fixture_drive() -> DriveId {
        DriveId::from_bytes([0xEE; 32])
    }

    fn fixture_transition() -> MembershipTransition {
        MembershipTransition::new(
            1,
            None,
            Vec::new(),
            vec![Change::Rotate],
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            DeviceId::from_bytes([0x44; 32]),
        )
        .expect("fixture transition")
    }

    fn fixture_snapshot() -> Snapshot {
        Snapshot::new(
            Vec::new(),
            ContentId::from_bytes([0x55; 32]),
            DeviceId::from_bytes([0x44; 32]),
            TransitionId::from_bytes([0x71; 32]),
            1,
            0,
            1,
        )
        .expect("fixture snapshot")
    }

    #[test]
    fn membership_challenge_for_matches_known_answer() {
        assert_eq!(
            hex::encode(membership_challenge_for(
                &fixture_transition(),
                &fixture_drive()
            )),
            "9655a54926643b8d477672c9e855826cd7e924876b7172c447c466aa7d7acc4f"
        );
    }

    #[test]
    fn snapshot_challenge_for_matches_known_answer() {
        assert_eq!(
            hex::encode(snapshot_challenge_for(
                &fixture_snapshot(),
                &fixture_drive()
            )),
            "986fd7f1133e023ffb2312b324763eab7629fa21bc4400cc65a5a052551cd9fd"
        );
    }
}
