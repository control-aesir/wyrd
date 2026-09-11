//! The presentation-agnostic daemon core: one drive's engine wired to
//! one read-only [`DriveView`] whose heads come from the classified
//! live-head seam ([`LiveHeads`]) — the eligible-head projection of the
//! observed DAG, never the raw announcement set, which is retained
//! history (`docs/epochs.md`).
//!
//! This is the composition the architecture docs assign to the daemon:
//! sync supplies durable state, keys, and fetch semantics; the view
//! supplies the filesystem-shaped read surface; neither learns about the
//! other's transport or presentation. Presentation backends (FUSE now,
//! mobile file surfaces later) consume the view and map errors at their
//! own boundary.

use wyrd_format::{ContentId, FetchStatus, ObjectStore, Snapshot};
use wyrd_fuse::{DriveView, Materialization, VerifiedSnapshot, ViewHead};
use wyrd_sync::durable::AuthorizedSnapshot;
use wyrd_sync::{bulk::BulkSource, runtime::Engine, transport::mailbox::Mailbox};

/// The classified live-head boundary: supplies the verified snapshot
/// bodies the authorization engine currently marks `Eligible` —
/// live-lineage DAG heads at the current epoch (`docs/epochs.md`).
///
/// Classification needs the membership log and the snapshot DAG, both of
/// which live in `wyrd-sync`; the daemon consumes the result and never
/// derives heads from announcements itself. The durable-snapshot-body
/// slice (issue `a4f41593`) turns this seam into an engine-backed
/// projection; the contract stays exactly this shape.
pub trait LiveHeads {
    type Error: std::fmt::Display;

    /// The verified snapshot bodies to install as the view's heads,
    /// typed as `AuthorizedSnapshot`: constructing one runs sync's
    /// signature verification, so a plugin cannot hand over an
    /// unverified body — rejections surface as plugin errors.
    fn live_heads(&mut self) -> Result<Vec<AuthorizedSnapshot>, Self::Error>;
}

/// The daemon's bridge from `wyrd-sync`'s verified snapshots to the
/// view's heads: the one in-tree implementation of [`VerifiedSnapshot`],
/// constructible only from an `AuthorizedSnapshot` — and only sync's
/// verification produces one of those. The field stays private: a
/// `LiveHead` is usable only by handing it to [`ViewHead::new`].
pub struct LiveHead(AuthorizedSnapshot);

impl LiveHead {
    pub fn new(verified: AuthorizedSnapshot) -> Self {
        Self(verified)
    }
}

// SAFETY: the sole in-tree implementation of the verification
// capability. `LiveHead` wraps `AuthorizedSnapshot`, and sync's BIP-340
// verification is the only thing that can construct one — the claim
// matches the type's own construction contract.
unsafe impl VerifiedSnapshot for LiveHead {
    fn into_snapshot(self) -> Snapshot {
        self.0.snapshot().clone()
    }
}

/// Bridge authorized snapshots into view heads. This is the only path
/// from the sync layer's verified bodies to the view: a raw `Snapshot`
/// cannot reach [`ViewHead`] in any downstream crate.
fn view_heads(heads: impl IntoIterator<Item = AuthorizedSnapshot>) -> Vec<ViewHead> {
    heads
        .into_iter()
        .map(LiveHead::new)
        .map(ViewHead::new)
        .collect()
}

/// How the daemon reports fetch status for content the local store
/// does not hold. Manifest-recorded content the store lacks is
/// `RemoteOnly`; the fetch state machine wiring (tracked separately)
/// will refine this into fetch-on-open behavior.
pub struct DaemonMaterialization {
    runtime: wyrd_sync::runtime::RuntimeState,
}

impl Materialization for DaemonMaterialization {
    fn status(&self, id: &ContentId) -> FetchStatus {
        self.runtime.status(id)
    }
}

/// One mounted drive: the engine (durable membership, keys, intake) plus
/// the read view over the shared object store. Every backend reads
/// through [`Daemon::view`].
pub struct Daemon<S: ObjectStore> {
    engine: Engine,
    view: DriveView<S, DaemonMaterialization>,
}

impl<S: ObjectStore> Daemon<S>
where
    S::Error: std::fmt::Debug,
{
    /// Compose the daemon from a running engine and the store it
    /// imports through. The store is shared: the engine imports
    /// verified bytes, the view serves them.
    pub fn new(engine: Engine, store: S) -> Self {
        let runtime = engine
            .runtime_state()
            .expect("engine runtime state must be readable during composition");
        let view = DriveView::new(store, DaemonMaterialization { runtime }, Vec::new());
        Daemon { engine, view }
    }

    /// The read-only drive view backends present.
    pub fn view(&self) -> &DriveView<S, DaemonMaterialization> {
        &self.view
    }

    /// Install verified snapshot heads directly. Use [`Daemon::refresh_heads`]
    /// when heads come from the classified live-head projection.
    pub fn set_heads(&mut self, heads: Vec<AuthorizedSnapshot>) {
        self.view.set_heads(view_heads(heads));
    }

    /// Drain control-plane messages and refresh the materialization projection.
    pub fn drain(
        &mut self,
        mailbox: &mut impl Mailbox,
    ) -> Result<wyrd_sync::runtime::DrainReport, wyrd_sync::runtime::EngineError> {
        let report = self.engine.drain(mailbox)?;
        self.refresh_materialization()?;
        Ok(report)
    }

    /// Refresh materialization facts after intake or fetch execution. Snapshot
    /// heads are supplied separately because announcements do not carry trees.
    pub fn refresh_materialization(&mut self) -> Result<(), wyrd_sync::runtime::EngineError> {
        self.view.set_materialization(DaemonMaterialization {
            runtime: self.engine.runtime_state()?,
        });
        Ok(())
    }

    /// Fetch verified manifests and objects, then refresh the view's local
    /// residency facts. Heads advance separately via [`Daemon::refresh_heads`].
    pub fn execute_plan<B: BulkSource>(
        &mut self,
        bulk: &mut B,
    ) -> Result<wyrd_sync::runtime::ExecuteReport, wyrd_sync::runtime::EngineError> {
        let report = self.engine.execute_plan(bulk, self.view.store_mut())?;
        self.refresh_materialization()?;
        Ok(report)
    }

    /// Install the classified live heads supplied by `source`. Durable
    /// announcements are history (canonical, superseded, voided,
    /// stranded); only the classified eligible set advances the live
    /// view.
    pub fn refresh_heads<P: LiveHeads>(&mut self, source: &mut P) -> Result<(), P::Error> {
        self.view.set_heads(view_heads(source.live_heads()?));
        Ok(())
    }

    /// Install the engine's classified live heads: the durable snapshot
    /// bodies the authorization engine marks `Eligible`, replayed and
    /// classified inside `wyrd-sync` (see [`Engine::live_heads`]). This
    /// is the engine-backed projection; [`Daemon::refresh_heads`] stays
    /// for non-engine sources.
    pub fn refresh_live_heads(&mut self) -> Result<(), wyrd_sync::runtime::EngineError> {
        self.view.set_heads(view_heads(self.engine.live_heads()?));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{
        Change, DeviceEncryptionKey, DeviceId, DriveId, Entry, MembershipTransition,
        MemoryObjectStore, ObjectKind, SnapshotId, TransitionId, Tree,
    };
    use wyrd_fuse::ViewError;
    use wyrd_sync::authorization::SnapshotDag;
    use wyrd_sync::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
    use wyrd_sync::membership::MembershipLog;

    // The trust.md challenge contexts. Wyrd-sync's signing helpers are
    // crate-private; the test pins the normative strings instead, and a
    // drift fails loudly as a bad signature.
    const MEMBER_CHALLENGE: &str = "wyrd membership challenge v1";
    const SNAPSHOT_CHALLENGE: &str = "wyrd snapshot challenge v1";

    /// An isolated engine over a scratch directory, removed by the caller
    /// after the daemon (and with it the store lock) is dropped.
    fn scratch_engine() -> (Engine, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wyrd-daemon-core-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let engine = Engine::open(
            dir.clone(),
            DriveId::from_bytes([0xEE; 32]),
            DeviceId::from_bytes([0xD0; 32]),
            "daemon-test",
            DeviceIdentitySecret::from_bytes([0x11; 32]).unwrap(),
            DeviceEncryptionSecret::from_bytes([0x22; 32]).unwrap(),
        )
        .unwrap();
        (engine, dir)
    }

    #[test]
    fn composition_serves_the_shared_store() {
        // A tree in the store is visible through the daemon's view once
        // its snapshot is a head. The author/transition bytes are
        // opaque to the view: the engine verified the announcements
        // that made these heads.
        let mut store = MemoryObjectStore::default();
        let hello = store.insert(ObjectKind::Chunk, b"hello").unwrap();
        let sub = Tree::from_entries(vec![Entry::file("a.txt", 5, false, vec![hello]).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        let root = Tree::from_entries(vec![Entry::dir("sub", sub).unwrap()])
            .unwrap()
            .insert_into(&mut store)
            .unwrap();
        // The head is signed by its author and authorized through the
        // sync layer, exactly as the composition requires: a raw
        // snapshot cannot reach the view.
        let (head_sk, head_author) = key_pair(0x0A);
        let drive = DriveId::from_bytes([0xEE; 32]);
        let mut head = Snapshot::new(
            Vec::new(),
            root,
            head_author,
            TransitionId::from_bytes([0x71; 32]),
            1,
            0,
            1,
        );
        sign_snapshot(&mut head, &head_sk, &drive);
        let head = AuthorizedSnapshot::authorize(head, &drive).unwrap();

        // Scratch engine: the daemon slice does not drive it yet, but
        // the composition holds the real dependency shape. The engine
        // holds no durable snapshot bodies, so the live-head projection
        // is empty and the view serves nothing.
        let (engine, dir) = scratch_engine();

        let mut daemon = Daemon::new(engine, store);
        daemon.refresh_live_heads().unwrap();
        assert_eq!(
            daemon.view().lookup("sub/a.txt"),
            Err(ViewError::NotFound),
            "an empty engine projects no heads"
        );

        daemon.set_heads(vec![head]);

        let node = daemon.view().lookup("sub/a.txt").unwrap();
        let file = daemon.view().open(&node).unwrap();
        assert_eq!(daemon.view().read(&file, 0, 5).unwrap(), b"hello");
        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn key_pair(byte: u8) -> (secp256k1::SecretKey, DeviceId) {
        let sk = secp256k1::SecretKey::from_slice(&[byte; 32]).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk);
        let (xonly, _) = secp256k1::XOnlyPublicKey::from_keypair(&kp);
        (sk, DeviceId::from_bytes(xonly.serialize()))
    }

    /// The device encryption key registered by an admission: the x-only
    /// public key of the device's test scalar (validity only needs a
    /// curve point; no capability is unwrapped in these tests).
    fn encryption_key(sk: &secp256k1::SecretKey) -> DeviceEncryptionKey {
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
        let (xonly, _) = secp256k1::XOnlyPublicKey::from_keypair(&kp);
        DeviceEncryptionKey::from_bytes(xonly.serialize())
    }

    fn sign_transition(t: &mut MembershipTransition, sk: &secp256k1::SecretKey, drive: &DriveId) {
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
        let challenge = blake3::derive_key(MEMBER_CHALLENGE, &t.signing_message(drive));
        t.signature = secp256k1::SECP256K1
            .sign_schnorr_no_aux_rand(&challenge, &kp)
            .to_byte_array();
    }

    fn sign_snapshot(s: &mut Snapshot, sk: &secp256k1::SecretKey, drive: &DriveId) {
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
        let challenge = blake3::derive_key(SNAPSHOT_CHALLENGE, &s.signing_message(drive));
        s.signature = secp256k1::SECP256K1
            .sign_schnorr_no_aux_rand(&challenge, &kp)
            .to_byte_array();
    }

    #[test]
    fn refresh_heads_installs_only_the_classified_live_heads() {
        // The live-head contract, end to end: a real membership log and
        // snapshot DAG built with the public API; the source classifies
        // with wyrd-sync's eligible-head projection and the daemon
        // installs the result. Chain parents, a superseded sibling, and
        // a voided branch are history; only the eligible head mounts.
        let drive = DriveId::from_bytes([0xEE; 32]);
        let (owner_sk, owner) = key_pair(0x10);
        let (second_sk, second) = key_pair(0x20);
        let (third_sk, third) = key_pair(0x30);

        // Membership: genesis (owner), a contested admission pair at
        // epoch 2, resolved in favor of the first branch. The loser's
        // transition is voided; snapshots bound to it never go live.
        let mut genesis = MembershipTransition {
            epoch: 1,
            prev: None,
            resolves: Vec::new(),
            changes: vec![
                Change::Admit(Admission {
                    device: owner,
                    encryption_key: encryption_key(&owner_sk),
                }),
                Change::SetOwners(vec![owner]),
            ],
            members_root: set_root(MEMBER_SET_CONTEXT, &[owner]),
            owners_root: set_root(OWNER_SET_CONTEXT, &[owner]),
            author: owner,
            signature: [0; 64],
        };
        sign_transition(&mut genesis, &owner_sk, &drive);
        let genesis_id = genesis.transition_id();

        let mut admit_second = MembershipTransition {
            epoch: 2,
            prev: Some(genesis_id),
            resolves: Vec::new(),
            changes: vec![Change::Admit(Admission {
                device: second,
                encryption_key: encryption_key(&second_sk),
            })],
            members_root: set_root(MEMBER_SET_CONTEXT, &[owner, second]),
            owners_root: set_root(OWNER_SET_CONTEXT, &[owner]),
            author: owner,
            signature: [0; 64],
        };
        sign_transition(&mut admit_second, &owner_sk, &drive);

        let mut admit_third = admit_second.clone();
        admit_third.changes = vec![Change::Admit(Admission {
            device: third,
            encryption_key: encryption_key(&third_sk),
        })];
        admit_third.members_root = set_root(MEMBER_SET_CONTEXT, &[owner, third]);
        sign_transition(&mut admit_third, &owner_sk, &drive);

        let mut resolution = MembershipTransition {
            epoch: 3,
            prev: Some(admit_second.transition_id()),
            resolves: vec![admit_third.transition_id()],
            changes: vec![Change::Rotate],
            members_root: set_root(MEMBER_SET_CONTEXT, &[owner, second]),
            owners_root: set_root(OWNER_SET_CONTEXT, &[owner]),
            author: owner,
            signature: [0; 64],
        };
        sign_transition(&mut resolution, &owner_sk, &drive);

        let mut log = MembershipLog::new(drive);
        for t in [&genesis, &admit_second, &admit_third, &resolution] {
            log.observe(t.clone());
        }

        let mut store = MemoryObjectStore::default();
        let tree = |store: &mut MemoryObjectStore, name: &str, body: &[u8]| {
            let chunk = store.insert(ObjectKind::Chunk, body).unwrap();
            Tree::from_entries(vec![Entry::file(
                name,
                body.len() as u64,
                false,
                vec![chunk],
            )
            .unwrap()])
            .unwrap()
            .insert_into(store)
            .unwrap()
        };
        let snap =
            |parents: Vec<SnapshotId>, tree: ContentId, membership: TransitionId, epoch: u64| {
                let mut s = Snapshot::new(parents, tree, owner, membership, epoch, 0, 1000 + epoch);
                sign_snapshot(&mut s, &owner_sk, &drive);
                s
            };

        let s0_tree = tree(&mut store, "s0.txt", b"0");
        let s1_tree = tree(&mut store, "s1.txt", b"1");
        let s2_tree = tree(&mut store, "s2.txt", b"2");
        let s3_tree = tree(&mut store, "s3.txt", b"3");
        let voided_tree = tree(&mut store, "voided.txt", b"v");
        let s4_tree = tree(&mut store, "s4.txt", b"4");

        let s0 = snap(Vec::new(), s0_tree, genesis_id, 1);
        let s1 = snap(vec![s0.snapshot_id()], s1_tree, genesis_id, 1);
        let s2 = snap(vec![s0.snapshot_id()], s2_tree, genesis_id, 1);
        let s3 = snap(
            vec![s1.snapshot_id()],
            s3_tree,
            admit_second.transition_id(),
            2,
        );
        let voided = snap(Vec::new(), voided_tree, admit_third.transition_id(), 2);
        let s4 = snap(
            vec![s3.snapshot_id()],
            s4_tree,
            resolution.transition_id(),
            3,
        );

        let mut dag = SnapshotDag::new(drive);
        let mut bodies = HashMap::new();
        for s in [&s0, &s1, &s2, &s3, &voided, &s4] {
            dag.observe(s.clone());
            bodies.insert(s.snapshot_id(), s.clone());
        }

        // What the engine-backed projection will be after the durable
        // snapshot-body slice: every announcement's body on hand, but
        // only the classified eligible set served.
        struct ClassifiedHeads {
            dag: SnapshotDag,
            log: MembershipLog,
            bodies: HashMap<SnapshotId, Snapshot>,
            drive: DriveId,
        }
        impl LiveHeads for ClassifiedHeads {
            type Error = std::convert::Infallible;

            fn live_heads(&mut self) -> Result<Vec<AuthorizedSnapshot>, Self::Error> {
                Ok(self
                    .dag
                    .eligible_heads(&self.log)
                    .into_iter()
                    .map(|id| {
                        AuthorizedSnapshot::authorize(self.bodies[&id].clone(), &self.drive)
                            .unwrap()
                    })
                    .collect())
            }
        }

        let (engine, dir) = scratch_engine();
        let mut daemon = Daemon::new(engine, store);
        daemon
            .refresh_heads(&mut ClassifiedHeads {
                dag,
                log,
                bodies,
                drive,
            })
            .unwrap();

        // The eligible head is the whole live view.
        let node = daemon.view().lookup("s4.txt").unwrap();
        let file = daemon.view().open(&node).unwrap();
        assert_eq!(daemon.view().read(&file, 0, 1).unwrap(), b"4");
        for gone in ["s0.txt", "s1.txt", "s2.txt", "s3.txt", "voided.txt"] {
            assert_eq!(
                daemon.view().lookup(gone),
                Err(ViewError::NotFound),
                "{gone}"
            );
        }
        drop(daemon);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
