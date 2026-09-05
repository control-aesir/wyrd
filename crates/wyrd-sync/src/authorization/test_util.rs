//! Test support for the snapshot authorization engine: a fixture that
//! drives the membership log (reusing the membership fixtures) and builds
//! signed snapshots bound to its canonical tip. Fixtures never use the
//! engine under test to construct themselves.

use secp256k1::{Keypair, SecretKey, SECP256K1};
use wyrd_format::{Change, ContentId, DeviceId, DriveId, Snapshot, SnapshotId, TransitionId};

use crate::membership::test_util::Builder;
use crate::membership::MembershipLog;

/// The BIP-340 challenge context for snapshots (trust.md).
pub(crate) const SNAPSHOT_CHALLENGE_CONTEXT: &str = "wyrd snapshot challenge v1";

pub(crate) fn snapshot_challenge(s: &Snapshot, drive: &DriveId) -> [u8; 32] {
    blake3::derive_key(SNAPSHOT_CHALLENGE_CONTEXT, &s.signing_message(drive))
}

/// Sign a snapshot in place with canonical BIP-340 nonces.
pub(crate) fn sign_snapshot(s: &mut Snapshot, sk: &SecretKey, drive: &DriveId) {
    let keypair = Keypair::from_secret_key(SECP256K1, sk);
    let sig = SECP256K1.sign_schnorr_no_aux_rand(&snapshot_challenge(s, drive), &keypair);
    s.signature = sig.to_byte_array();
}

/// A dummy root-tree ContentId for fixtures.
pub(crate) fn tree_id(pattern: u8) -> ContentId {
    ContentId::from_bytes([pattern; 32])
}

/// Drives the membership log with the fixture owner and builds snapshots
/// bound to the canonical tip.
pub(crate) struct Fixture {
    pub drive: DriveId,
    pub sk: SecretKey,
    pub owner: DeviceId,
    pub builder: Builder,
    pub log: MembershipLog,
    pub tip: TransitionId,
    pub tip_epoch: u64,
}

impl Fixture {
    /// A drive with its genesis transition observed (K = 1) and a genesis
    /// snapshot.
    pub fn new(sk_byte: u8) -> Self {
        let (builder, genesis) = Builder::genesis(sk_byte);
        let owner = *builder.owners.iter().next().unwrap();
        let mut log = MembershipLog::new(builder.drive);
        log.observe(genesis);
        let tip = log.known_state().expect("genesis observed").transition_id;
        Fixture {
            drive: builder.drive,
            sk: builder.sk,
            owner,
            builder,
            log,
            tip,
            tip_epoch: 1,
        }
    }

    /// Apply a membership change: observes the transition and advances
    /// the tip.
    pub fn membership(&mut self, changes: Vec<Change>) {
        let t = self.builder.child(changes);
        self.observe_raw(t);
    }

    /// Observe an externally built transition (forks, resolutions) and
    /// refresh the tip from the log.
    pub fn observe_raw(&mut self, t: wyrd_format::MembershipTransition) {
        self.log.observe(t);
        let known = self
            .log
            .known_state()
            .expect("fixture keeps a canonical tip");
        self.tip = known.transition_id;
        self.tip_epoch = known.epoch;
    }

    /// Build a snapshot bound to the canonical tip.
    #[allow(clippy::too_many_arguments)]
    pub fn snapshot(
        &self,
        parents: Vec<SnapshotId>,
        tree: ContentId,
        author: DeviceId,
        author_sk: &SecretKey,
        flags: u8,
    ) -> Snapshot {
        let mut s = Snapshot::new(
            parents,
            tree,
            author,
            self.tip,
            self.tip_epoch,
            flags,
            1000 + self.tip_epoch,
        );
        sign_snapshot(&mut s, author_sk, &self.drive);
        s
    }

    /// A snapshot by the fixture owner.
    pub fn owner_snapshot(&self, parents: Vec<SnapshotId>, tree: ContentId) -> Snapshot {
        self.snapshot(parents, tree, self.owner, &self.sk, 0)
    }

    /// A device key for admit/remove/author fixtures.
    pub fn device(&self, byte: u8) -> (SecretKey, DeviceId) {
        crate::membership::test_util::key(byte)
    }
}
