//! Drive open and membership: bootstrap delegation plus the owner-signed membership transitions.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use wyrd_format::{DeviceEncryptionKey, DeviceId, DriveId, MembershipTransition, TransitionId};
use zeroize::Zeroizing;

use crate::control::ControlInbox;
use crate::durable::DurableStore;
use crate::keys::{DeviceEncryptionSecret, DeviceIdentitySecret};
use crate::membership::MembershipLog;
use crate::membership::TransitionStatus;

use super::super::{author, bootstrap};
use super::{Engine, EngineError, PairingRequest, PendingQueue};

impl Engine {
    /// Open (or create) the engine state: the durable store plus the
    /// inbox dedupe set and membership log rehydrated from committed
    /// facts. `identity_secret` opens NIP-44 envelopes addressed to
    /// `device`; `encryption_secret` unwraps capabilities for it.
    pub fn open(
        dir: PathBuf,
        drive: DriveId,
        device: DeviceId,
        passphrase: &str,
        identity_secret: DeviceIdentitySecret,
        encryption_secret: DeviceEncryptionSecret,
    ) -> Result<Self, EngineError> {
        let store = DurableStore::open(dir, drive, passphrase)?;
        Self::open_with_store(store, drive, device, identity_secret, encryption_secret)
    }

    /// Assemble an engine over an already-open durable store. The caller
    /// holds the store lock: bootstrap acquires it before writing any
    /// drive or custody state (so creation is serialized) and before
    /// reading the custody record on open (so the read is serialized
    /// against writers).
    pub(in crate::runtime) fn open_with_store(
        store: DurableStore,
        drive: DriveId,
        device: DeviceId,
        identity_secret: DeviceIdentitySecret,
        encryption_secret: DeviceEncryptionSecret,
    ) -> Result<Self, EngineError> {
        let vault = crate::serving::Vault::open(store.dir())?;
        let mut engine = Engine {
            drive,
            device,
            identity_secret,
            encryption_secret,
            // Owner flows set this after open (create, open_keystore);
            // member and keystoreless opens keep `None` and escrow
            // nothing.
            root: None,
            store,
            vault,
            inbox: ControlInbox::new(drive),
            epoch_keys: BTreeMap::new(),
            log: MembershipLog::new(drive),
            announcements: BTreeMap::new(),
            committed_capabilities: BTreeMap::new(),
            received_requests: BTreeSet::new(),
            answered_statements: BTreeSet::new(),
            stalled_statements: BTreeSet::new(),
            answered_upto: 0,
            pending: PendingQueue::default(),
            fetch_run: 0,
            fetch_strikes: BTreeMap::new(),
            fetch_budget_burns: BTreeMap::new(),
            fetch_cool_until: BTreeMap::new(),
            fetch_generations: BTreeMap::new(),
            fetch_terminal: BTreeMap::new(),
            fetch_attempted: BTreeSet::new(),
            fetch_invalid_cooled: BTreeSet::new(),
            fetch_budget_cooled: BTreeSet::new(),
            fetch_transport_seen: BTreeSet::new(),
            refusal_warned: HashSet::new(),
            #[cfg(test)]
            crash_stage: None,
            #[cfg(test)]
            crash_skip: 0,
            reconnect_latched: false,
            last_requested_digest: None,
            last_trigger_eval: None,
        };
        engine.resync()?;
        engine.restore_epoch_keys()?;
        Ok(engine)
    }

    /// Derive control keys for every durably held epoch secret. The
    /// keyring survives restarts but the per-process keys do not, so
    /// without this a reopened engine stalls previously receivable
    /// traffic as skipped until a fresh capability happens to arrive.
    /// Derivation is deterministic — reopening installs identical keys
    /// — and authorization already happened when each secret was
    /// installed.
    fn restore_epoch_keys(&mut self) -> Result<(), EngineError> {
        let rebuilt = self.store.rebuild(self.device)?;
        for epoch in 1..=rebuilt.keyring.up_to() {
            if let Some(secret) = rebuilt.keyring.secret(epoch) {
                self.add_epoch_key(
                    epoch,
                    Zeroizing::new(secret.control_key(&self.drive, epoch)),
                );
            }
        }
        Ok(())
    }

    /// Create a new single-device drive. `identity` is the owner's Nostr
    /// identity (the signer's key, trust.md T6). The device encryption
    /// secret and the drive root are generated and persisted under
    /// `passphrase`, and the epoch-1 secret is escrowed under the root, so
    /// the drive survives the creating process. Fails if `dir` already
    /// holds a drive. The drive starts headless; author the first snapshot
    /// with [`Engine::author_snapshot`].
    pub fn create(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
    ) -> Result<Engine, EngineError> {
        bootstrap::create(dir, passphrase, identity)
    }

    /// Open a drive created by [`Engine::create`]: the drive id, root, and
    /// device encryption secret come from the drive directory, and the
    /// epoch-1 secret is recovered from escrow under the root. The caller
    /// supplies the identity secret (the signer's key).
    pub fn open_keystore(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
    ) -> Result<Engine, EngineError> {
        bootstrap::open_keystore(dir, passphrase, identity)
    }

    /// Join a drive as an invited device: open the owner's sealed
    /// invitation, commit its genesis, and install the invited epoch
    /// control keys so the first mailbox drain can open the catch-up
    /// set. See [`bootstrap::accept_invitation`] for the trust
    /// reasoning. The admission transition and the capability's
    /// authorization arrive through the normal intake path afterwards —
    /// this call commits no capability fact.
    pub fn accept_invitation(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
        encryption: DeviceEncryptionSecret,
        sealed: &crate::control::SealedBootstrap,
    ) -> Result<Engine, EngineError> {
        bootstrap::accept_invitation(dir, passphrase, identity, encryption, sealed)
    }

    /// Stage (or reuse) this device's pairing secret and return the
    /// public pairing material for the owner. See
    /// [`bootstrap::pairing_request`]: re-running returns the
    /// same key, never a fresh one.
    pub fn pairing_request(
        dir: &Path,
        passphrase: &str,
        identity: &DeviceIdentitySecret,
    ) -> Result<PairingRequest, EngineError> {
        bootstrap::pairing_request(dir, passphrase, identity)
    }

    /// Join a drive from the staged pairing secret plus the owner's
    /// sealed invitation: member custody persists before the accept
    /// commits, so the joined device reopens afterwards. See
    /// [`bootstrap::join`] for the ordering and refusal rules.
    pub fn join(
        dir: PathBuf,
        passphrase: &str,
        identity: DeviceIdentitySecret,
        sealed: &crate::control::SealedBootstrap,
    ) -> Result<Engine, EngineError> {
        bootstrap::join(dir, passphrase, identity, sealed)
    }

    /// Reissue a device's sealed invitation from durable state: the
    /// recovery path for an admission whose invitation never reached
    /// a file. Authors nothing; see
    /// [`author::reissue_invitation`].
    pub fn reissue_invitation(
        &self,
        device: DeviceId,
    ) -> Result<crate::control::SealedBootstrap, EngineError> {
        author::reissue_invitation(self, device)
    }

    /// Admit a device to the drive: author, sign, and commit the
    /// admission transition (exactly one new epoch), install the new
    /// epoch's self capability, and return the signed transition plus
    /// the sealed invitation for out-of-band delivery to the newcomer.
    /// Only an owner admits. See [`author::admit_device`].
    pub fn admit_device(
        &mut self,
        device: DeviceId,
        encryption_key: DeviceEncryptionKey,
    ) -> Result<author::AdmitOutcome, EngineError> {
        author::admit_device(self, device, encryption_key)
    }

    /// Admit a device as a reader: the same commit path as
    /// [`Engine::admit_device`], with a reader-tagged change. The
    /// invitation, capability grant, and catch-up are identical — the
    /// role lives in the membership log, and the authorship gates
    /// (local and peer) enforce it from there. Only an owner admits.
    /// See [`author::admit_reader`].
    pub fn admit_reader(
        &mut self,
        device: DeviceId,
        encryption_key: DeviceEncryptionKey,
    ) -> Result<author::AdmitOutcome, EngineError> {
        author::admit_reader(self, device, encryption_key)
    }

    /// Recover one interrupted admission: verify the supplied
    /// encryption key and role against the device's canonical
    /// admission (identity guard — key or role mismatch refuses
    /// rather than recovering the wrong identity), resume its
    /// catch-up fill, and reissue its invitation. The operator
    /// surface for `member invite` reruns after a crash between the
    /// membership commit and a complete fill. See
    /// [`author::resume_admission`].
    pub fn resume_admission(
        &mut self,
        device: DeviceId,
        expected_key: &DeviceEncryptionKey,
        expect_reader: bool,
    ) -> Result<author::ResumeOutcome, EngineError> {
        author::resume_admission(self, device, expected_key, expect_reader)
    }

    /// Remove a device from the drive: author, sign, and commit the
    /// removal transition (exactly one new epoch), install the new
    /// epoch's self capability when this device remains a member, and
    /// queue catch-up for the remaining members and readers. The
    /// removed device — member or reader — receives no new-epoch
    /// material. Only an owner removes; removing the sole owner is
    /// valid but terminal. See [`author::remove_device`].
    pub fn remove_device(&mut self, device: DeviceId) -> Result<MembershipTransition, EngineError> {
        author::remove_device(self, device)
    }

    /// Force a fresh epoch secret: author, sign, and commit the
    /// rotation transition (exactly one new epoch), reinstall the new
    /// epoch's self capability, and queue catch-up for every other
    /// admitted device. Membership is unchanged. Only an owner rotates. See
    /// [`author::rotate_epoch`].
    pub fn rotate_epoch(&mut self) -> Result<MembershipTransition, EngineError> {
        author::rotate_epoch(self)
    }

    /// Hand ownership to another member: author, sign, and commit the
    /// owner-set transition (exactly one new epoch), install the new
    /// epoch's self capability when this device remains a member, and
    /// queue catch-up for the remaining members. v0 ownership is a
    /// singleton. Only the current owner hands over, and only to a
    /// member. See [`author::set_owners`].
    pub fn set_owners(&mut self, new_owner: DeviceId) -> Result<MembershipTransition, EngineError> {
        author::set_owners(self, new_owner)
    }

    /// Resolve a frozen membership conflict: author, sign, and commit
    /// the owner-signed resolution naming the winning tip in `prev`
    /// and exactly the voided siblings in `resolves` (one new epoch,
    /// membership unchanged apart from the voiding). Only an owner
    /// resolves, and only a live contender wins. See
    /// [`author::resolve_conflict`].
    pub fn resolve_conflict(
        &mut self,
        winner: TransitionId,
        voided: Vec<TransitionId>,
    ) -> Result<MembershipTransition, EngineError> {
        author::resolve_conflict(self, winner, voided)
    }

    /// The live contenders the frozen membership epoch waits on,
    /// ascending: the rival tips `member status` lists and `member
    /// resolve` names. Empty when nothing is frozen. One derivation
    /// shared by display and authoring, so the status view can never
    /// list a rival the resolver then refuses.
    pub fn frozen_contenders(&self) -> Vec<TransitionId> {
        let Some(epoch) = self.log.frozen_at() else {
            return Vec::new();
        };
        let mut rivals: Vec<TransitionId> = self
            .log
            .statuses()
            .into_iter()
            .filter_map(|(id, status)| {
                if !matches!(status, TransitionStatus::Contested) {
                    return None;
                }
                let transition = self.log.transition(&id)?;
                (transition.epoch == epoch).then_some(id)
            })
            .collect();
        rivals.sort();
        rivals
    }
}
