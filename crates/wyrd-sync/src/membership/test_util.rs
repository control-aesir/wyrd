//! Test support for membership-machine tests: deterministic test keys and
//! a chain builder that mirrors the change rules *independently* of the
//! code under test, so fixtures never trust the implementation. Malformed
//! transitions are hand-built with struct literals plus [`sign`].

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{Change, DeviceId, DriveId, MembershipTransition, TransitionId};

/// The BIP-340 challenge context for membership transitions (trust.md).
pub(crate) const CHALLENGE_CONTEXT: &str = "wyrd membership challenge v1";

/// The 32-byte BIP-340 challenge for a transition's signing message.
pub(crate) fn challenge(t: &MembershipTransition, drive: &DriveId) -> [u8; 32] {
    blake3::derive_key(CHALLENGE_CONTEXT, &t.signing_message(drive))
}

/// Sign a transition in place with canonical BIP-340 nonces (no auxiliary
/// randomness), exactly as the machine expects.
pub(crate) fn sign(t: &mut MembershipTransition, sk: &SecretKey, drive: &DriveId) {
    let keypair = Keypair::from_secret_key(SECP256K1, sk);
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&challenge(t, drive), &keypair);
    t.signature = sig.to_byte_array();
}

/// A deterministic key: secret key and the DeviceId it names. Test scalars
/// are small constants; never use outside tests.
pub(crate) fn key(byte: u8) -> (SecretKey, DeviceId) {
    let sk = SecretKey::from_slice(&[byte; 32]).expect("valid test scalar");
    let keypair = Keypair::from_secret_key(SECP256K1, &sk);
    let xonly = XOnlyPublicKey::from_keypair(&keypair).0;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&xonly.serialize());
    (sk, DeviceId::from_bytes(bytes))
}

/// The shared test drive id (all fixtures use the same drive).
pub(crate) fn drive() -> DriveId {
    DriveId::from_bytes([0xEE; 32])
}

/// Builds a signed transition chain, tracking member/owner sets itself so
/// fixtures are independent of the machine under test. The mirror is
/// deliberately dumb (no invariant checks): tests that need invalid
/// declared states build them explicitly.
pub(crate) struct Builder {
    pub drive: DriveId,
    pub sk: SecretKey,
    pub members: BTreeSet<DeviceId>,
    pub owners: BTreeSet<DeviceId>,
    pub prev: Option<TransitionId>,
    pub epoch: u64,
}

impl Builder {
    /// The signed genesis transition for a single owner.
    pub fn genesis(sk_byte: u8) -> (Self, MembershipTransition) {
        let (sk, owner) = key(sk_byte);
        let drive = drive();
        let mut t = MembershipTransition {
            epoch: 1,
            prev: None,
            resolves: Vec::new(),
            changes: vec![Change::Admit(owner), Change::SetOwners(vec![owner])],
            members_root: set_root(MEMBER_SET_CONTEXT, &[owner]),
            owners_root: set_root(OWNER_SET_CONTEXT, &[owner]),
            author: owner,
            signature: [0; 64],
        };
        sign(&mut t, &sk, &drive);
        (
            Builder {
                drive,
                sk,
                members: [owner].into(),
                owners: [owner].into(),
                prev: Some(t.transition_id()),
                epoch: 1,
            },
            t,
        )
    }

    /// The signed next transition, mirroring the changes into the tracked
    /// sets and deriving the roots from the result. Signed by the tracked
    /// owner with the genesis key — authority from the PRE-transition
    /// owner set, exactly as the machine expects.
    pub fn child(&mut self, changes: Vec<Change>) -> MembershipTransition {
        let author = *self.owners.iter().next().expect("tracked owner");
        self.apply_mirror(&changes);
        let mut t = MembershipTransition {
            epoch: self.epoch + 1,
            prev: self.prev,
            resolves: Vec::new(),
            changes,
            members_root: set_root(
                MEMBER_SET_CONTEXT,
                &self.members.iter().copied().collect::<Vec<_>>(),
            ),
            owners_root: set_root(
                OWNER_SET_CONTEXT,
                &self.owners.iter().copied().collect::<Vec<_>>(),
            ),
            author,
            signature: [0; 64],
        };
        sign(&mut t, &self.sk, &self.drive);
        self.prev = Some(t.transition_id());
        self.epoch = t.epoch;
        t
    }

    /// Mirror the changes into the tracked sets without invariant checks
    /// (invalid fixtures are hand-built). The sole-owner removal cascade
    /// is mirrored so valid fixtures' declared roots match the derived
    /// ones.
    fn apply_mirror(&mut self, changes: &[Change]) {
        for change in changes {
            match change {
                Change::Admit(d) => {
                    self.members.insert(*d);
                }
                Change::Remove(d) => {
                    self.members.remove(d);
                    if self.owners.contains(d) && self.owners.len() == 1 {
                        self.owners.clear();
                    }
                }
                Change::Rotate => {}
                Change::SetOwners(owners) => {
                    self.owners = owners.iter().copied().collect();
                }
            }
        }
    }
}
