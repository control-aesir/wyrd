//! Test support for membership-machine tests: deterministic test keys and
//! a chain builder that mirrors the change rules *independently* of the
//! code under test, so fixtures never trust the implementation. Malformed
//! transitions are hand-built with struct literals plus [`sign`].

use secp256k1::{Keypair, SecretKey, XOnlyPublicKey, SECP256K1};
use std::collections::BTreeSet;
use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
use wyrd_format::{
    Change, DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition, TransitionId,
};

/// A deterministic device encryption key for fixtures: the x-only pubkey
/// of a test scalar derived as `BLAKE3("wyrd test encryption key
/// v1" || device || counter)`, retried until it is a valid secp256k1
/// scalar. Deliberately decoupled from the device fixture's byte pattern:
/// changing `key()` must never silently invalidate (or collide) this key.
/// Test-only.
pub(crate) fn admit(device: DeviceId) -> Change {
    let mut counter = 0u8;
    let sk = loop {
        let mut input = Vec::with_capacity(32 + device.as_bytes().len() + 1);
        input.extend_from_slice(b"wyrd test encryption key v1");
        input.extend_from_slice(device.as_bytes());
        input.push(counter);
        let hash = blake3::hash(&input);
        if let Ok(sk) = SecretKey::from_slice(hash.as_bytes()) {
            break sk;
        }
        counter = counter.checked_add(1).expect("test scalar space exhausted");
    };
    let keypair = Keypair::from_secret_key(SECP256K1, &sk);
    Change::Admit(Admission {
        device,
        encryption_key: DeviceEncryptionKey::from_bytes(
            XOnlyPublicKey::from_keypair(&keypair).0.serialize(),
        ),
    })
}

/// Sign a transition in place: delegate to the production helper so the
/// fixture and the genesis bootstrap cannot drift on the pinned challenge.
pub(crate) fn sign(t: &mut MembershipTransition, sk: &SecretKey, drive: &DriveId) {
    super::validate::sign_transition(t, sk, drive);
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
        let mut t = MembershipTransition::new(
            1,
            None,
            Vec::new(),
            vec![admit(owner), Change::SetOwners(vec![owner])],
            set_root(MEMBER_SET_CONTEXT, &[owner]),
            set_root(OWNER_SET_CONTEXT, &[owner]),
            owner,
        )
        .unwrap();
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
        let mut t = MembershipTransition::new(
            self.epoch + 1,
            self.prev,
            Vec::new(),
            changes,
            set_root(
                MEMBER_SET_CONTEXT,
                &self.members.iter().copied().collect::<Vec<_>>(),
            ),
            set_root(
                OWNER_SET_CONTEXT,
                &self.owners.iter().copied().collect::<Vec<_>>(),
            ),
            author,
        )
        .unwrap();
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
                Change::Admit(admission) => {
                    self.members.insert(admission.device);
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
