//! Control-plane intake and message classification for the runtime engine.

use wyrd_format::MembershipTransition;

use super::engine::{DrainReport, Engine, EngineError};
use crate::control::{ControlMessageId, IngestReport, Message, SealedControl};
use crate::durable::{AuthorizedCapability, Fact};
use crate::ingest::{check_total_len, check_transition, Limits};
use crate::keys::capability::WrappedCapability;
use crate::membership::TransitionStatus;
use crate::transport::mailbox::{open_from_sender, Mailbox, MailboxEnvelope};

const MAX_PENDING_MESSAGES: usize = super::engine::MAX_PENDING_MESSAGES;

enum Action {
    Commit(Vec<Fact>),
    Defer,
}

enum Outcome {
    Accepted,
    Duplicate,
    Deferred,
    Skipped,
}

pub(super) fn drain(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<DrainReport, EngineError> {
    let mut report = DrainReport::default();
    while let Some(envelope) = mailbox.recv() {
        match accept_envelope(engine, &envelope)? {
            Outcome::Accepted => report.accepted += 1,
            Outcome::Duplicate => report.duplicates += 1,
            Outcome::Deferred => report.deferred += 1,
            Outcome::Skipped => report.skipped += 1,
        }
    }
    Ok(report)
}

fn accept_envelope(
    engine: &mut Engine,
    envelope: &MailboxEnvelope,
) -> Result<Outcome, EngineError> {
    let bytes = match open_from_sender(&engine.identity_secret, engine.device, envelope) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Outcome::Skipped),
    };
    match engine.inbox.ingest(&bytes) {
        Err(_) => Ok(Outcome::Skipped),
        Ok(IngestReport::Duplicate) => match sealed_id(&bytes) {
            Some(id) => match engine.pending.remove(&id) {
                Some(message) => commit_action(engine, &id, &message, false),
                None => Ok(Outcome::Duplicate),
            },
            None => Ok(Outcome::Duplicate),
        },
        Ok(IngestReport::Accepted { id, message }) => commit_action(engine, &id, &message, true),
    }
}

fn commit_action(
    engine: &mut Engine,
    id: &ControlMessageId,
    message: &Message,
    is_new: bool,
) -> Result<Outcome, EngineError> {
    let mut facts = match message_action(engine, id, message) {
        Action::Commit(facts) => facts,
        Action::Defer if engine.pending.len() >= MAX_PENDING_MESSAGES => {
            vec![Fact::ControlMessage(*id)]
        }
        Action::Defer => {
            engine.pending.insert(*id, message.clone());
            return Ok(Outcome::Deferred);
        }
    };
    if !is_new {
        facts.clear();
    }
    if matches!(message, Message::MembershipTransition(_)) {
        for (pending_id, pending_message) in std::mem::take(&mut engine.pending) {
            match message_action(engine, &pending_id, &pending_message) {
                Action::Commit(more) => facts.extend(more),
                Action::Defer => {
                    engine.pending.insert(pending_id, pending_message);
                }
            }
        }
    }
    if facts.is_empty() {
        return Ok(Outcome::Duplicate);
    }
    if let Err(error) = engine.commit_facts(&facts) {
        let _ = engine.resync();
        return Err(error.into());
    }
    Ok(Outcome::Accepted)
}

fn message_action(engine: &mut Engine, id: &ControlMessageId, message: &Message) -> Action {
    match message {
        Message::MembershipTransition(payload) => {
            let seen = || vec![Fact::ControlMessage(*id)];
            if check_total_len(&Limits::V0, "transition", payload.transition.len()).is_err() {
                return Action::Commit(seen());
            }
            let transition = match MembershipTransition::from_canonical_bytes(&payload.transition) {
                Ok(transition) => transition,
                Err(_) => return Action::Commit(seen()),
            };
            if check_transition(&Limits::V0, &transition).is_err() {
                return Action::Commit(seen());
            }
            engine.log.observe(transition.clone());
            Action::Commit(vec![
                Fact::Transition(transition),
                Fact::ControlMessage(*id),
            ])
        }
        Message::SnapshotAnnouncement(announcement) => {
            match engine.log.transition(&announcement.membership) {
                None => Action::Defer,
                Some(t) if t.epoch != announcement.epoch => {
                    Action::Commit(vec![Fact::ControlMessage(*id)])
                }
                Some(_) => match engine
                    .log
                    .status(&announcement.membership)
                    .expect("membership observed")
                {
                    TransitionStatus::Canonical => Action::Commit(vec![
                        Fact::Announcement(announcement.clone()),
                        Fact::ControlMessage(*id),
                    ]),
                    TransitionStatus::Invalid(_) => Action::Commit(vec![Fact::ControlMessage(*id)]),
                    TransitionStatus::Contested
                    | TransitionStatus::Voided
                    | TransitionStatus::Orphaned
                    | TransitionStatus::Pending => Action::Defer,
                },
            }
        }
        Message::KeyRotation(_) => Action::Commit(vec![Fact::ControlMessage(*id)]),
        Message::Capability(_) => capability_action(engine, id, message),
    }
}

fn capability_action(engine: &Engine, id: &ControlMessageId, message: &Message) -> Action {
    let Message::Capability(payload) = message else {
        return Action::Defer;
    };
    let capability = match WrappedCapability::from_bytes(payload.wrapped.clone())
        .unwrap(&engine.encryption_secret)
    {
        Ok(capability) => capability,
        Err(_) => return Action::Commit(vec![Fact::ControlMessage(*id)]),
    };
    // Redundant-field agreement, mirrored from the control envelope
    // (T15): the sealed payload's device and epoch are authenticated
    // delivery metadata and must match the capability they deliver. A
    // disagreement is tampering or a broken sender — it never heals by
    // deferring, so suppress without a durable capability fact.
    if payload.device != capability.device || payload.epoch != capability.covered_epoch() {
        return Action::Commit(vec![Fact::ControlMessage(*id)]);
    }
    let state = match engine.log.state_of(&capability.transition) {
        Some(state) => state,
        None => return Action::Defer,
    };
    match AuthorizedCapability::authorize(capability, &state) {
        Ok(authorized) => Action::Commit(vec![
            Fact::Capability(authorized),
            Fact::ControlMessage(*id),
        ]),
        Err(_) => Action::Commit(vec![Fact::ControlMessage(*id)]),
    }
}

fn sealed_id(bytes: &[u8]) -> Option<ControlMessageId> {
    SealedControl::decode(bytes)
        .ok()
        .map(|sealed| sealed.message_id())
}

#[cfg(test)]
mod tests {
    use super::*;

    use secp256k1::SecretKey;
    use wyrd_format::membership::{set_root, Admission, MEMBER_SET_CONTEXT, OWNER_SET_CONTEXT};
    use wyrd_format::{Change, DeviceId, TransitionId};

    use crate::control::{CapabilityPayload, Message, TransitionPayload};
    use crate::keys::capability::Capability;
    use crate::keys::EpochSecret;
    use crate::membership::test_util::{drive as member_drive, key, sign, Builder};
    use crate::membership::MembershipLog;
    use crate::runtime::test_util::{
        admit_engine, announcement_for, capability_message, control_key, deliver, drain,
        encryption_key, fixture, owner, queue, reopen, transition_message, MemoryMailbox,
    };
    /// Hand-sign one transition against the fixture drive (mirrors
    /// the conformance helper): for siblings the builder cannot
    /// produce.
    #[allow(clippy::too_many_arguments)]
    fn signed(
        epoch: u64,
        prev: Option<TransitionId>,
        resolves: Vec<TransitionId>,
        changes: Vec<Change>,
        members: &[DeviceId],
        owners: &[DeviceId],
        author_sk: &SecretKey,
        author: DeviceId,
    ) -> MembershipTransition {
        let mut t = MembershipTransition {
            epoch,
            prev,
            resolves,
            changes,
            members_root: set_root(MEMBER_SET_CONTEXT, members),
            owners_root: set_root(OWNER_SET_CONTEXT, owners),
            author,
            signature: [0; 64],
        };
        sign(&mut t, author_sk, &member_drive());
        t
    }

    #[test]
    fn intake_commits_transitions_and_announcements() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        let bound = announcement_for(2, child.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(
            report,
            DrainReport {
                accepted: 3,
                duplicates: 0,
                deferred: 0,
                skipped: 0,
            }
        );
        assert_eq!(fixture.engine.current(), 3);
    }

    #[test]
    fn redelivery_after_restart_stays_duplicate() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        // The same sealed bytes are queued twice: a fresh seal would
        // mint a fresh nonce and therefore a new message id.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
        ];
        queue(&mut fixture, mail.clone());
        assert_eq!(drain(&mut fixture).accepted, 2);

        // Simulated restart, then redelivery of the same envelopes:
        // rehydrated dedupe makes every replay a duplicate.
        let mut engine = reopen(&mut fixture);
        queue(&mut fixture, mail);
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        let report = engine.drain(&mut mailbox).unwrap();
        assert_eq!(report.duplicates, 2);
        assert_eq!(report.accepted, 0);
        assert_eq!(engine.current(), 2);
    }

    #[test]
    fn unknown_epoch_skips_without_commit_then_lands() {
        let mut fixture = fixture();
        // A nine-deep chain: the announcement binds epoch 9 to the
        // epoch-9 tip, whose key the engine does not hold yet.
        let (mut builder, genesis) = Builder::genesis(10);
        let mut chain = vec![genesis];
        for _ in 1..9 {
            chain.push(builder.child(vec![Change::Rotate]));
        }
        let tip = chain.last().expect("nonempty chain").clone();
        let bound = announcement_for(9, tip.transition_id());
        let mail = vec![deliver(&fixture, 9, &bound)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.accepted, 0);
        assert_eq!(fixture.engine.current(), 0);

        // The epoch key arrives with the chain behind it: the
        // transitions commit, then the announcement validates.
        fixture.engine.add_epoch_key(9, control_key(9));
        let mut mail: Vec<MailboxEnvelope> = chain
            .iter()
            .map(|t| deliver(&fixture, 1, &transition_message(t)))
            .collect();
        mail.push(deliver(&fixture, 9, &bound));
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 10);
        assert_eq!(fixture.engine.current(), 10);
    }

    #[test]
    fn forged_envelope_skips_without_commit() {
        let mut fixture = fixture();
        let genesis_id = Builder::genesis(10).1.transition_id();
        let mut envelope = deliver(&fixture, 1, &announcement_for(1, genesis_id));
        // Truncation breaks the base64 framing deterministically, so
        // the transport seal can never open.
        envelope.ciphertext.pop();
        queue(&mut fixture, vec![envelope]);
        let report = drain(&mut fixture);
        assert_eq!(report.skipped, 1);
        assert_eq!(fixture.engine.current(), 0);
    }

    #[test]
    fn garbage_transition_suppresses_redelivery() {
        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let mut poisoned = genesis.canonical_bytes();
        poisoned[10] ^= 0xFF;
        // The same sealed bytes are queued twice: a fresh seal would
        // mint a fresh nonce and therefore a new message id.
        let mail = vec![deliver(
            &fixture,
            1,
            &Message::MembershipTransition(TransitionPayload {
                transition: poisoned,
            }),
        )];
        queue(&mut fixture, mail.clone());
        // Undecodable bytes commit a seen-id suppression...
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.current(), 1);
        // ...so redelivery is a duplicate, never reprocessed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.accepted, 0);
        assert_eq!(fixture.engine.current(), 1);
    }

    #[test]
    fn capability_defers_until_its_transition_lands() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // Admit the engine device on-chain with its encryption key.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });

        // Capability first: its transition is unobserved, so it holds.
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        assert_eq!(fixture.engine.current(), 0);

        // The transitions land: both commit, and the held capability
        // authorizes against the new state in the same pass.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        assert_eq!(fixture.engine.current(), 2);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.capabilities.len(), 1);
    }

    #[test]
    fn announcement_defers_until_membership_lands() {
        let mut fixture = fixture();
        let (mut builder, genesis) = Builder::genesis(10);
        let child = builder.child(vec![Change::Rotate]);
        let bound = announcement_for(2, child.transition_id());

        // Announcement first: its membership is unobserved, so it holds.
        let mail = vec![deliver(&fixture, 2, &bound)];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        assert_eq!(fixture.engine.current(), 0);

        // The transitions land: both commit, and the held announcement
        // validates against the new state in the same pass.
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&child)),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        assert_eq!(fixture.engine.current(), 2);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), 1);
    }

    #[test]
    fn announcement_epoch_mismatch_suppresses() {
        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 1);

        // Epoch 2 claimed against an epoch-1 transition: transition
        // epochs are immutable, so this suppresses rather than parks.
        let bad = announcement_for(2, genesis_id);
        let mail = vec![deliver(&fixture, 2, &bad)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn pending_holds_are_bounded() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // A well-formed capability for a transition the engine never
        // observes: every redelivery defers under a distinct message
        // id (fresh seal nonces).
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mut mail = Vec::with_capacity(MAX_PENDING_MESSAGES + 1);
        for _ in 0..=MAX_PENDING_MESSAGES {
            mail.push(deliver(&fixture, 2, &delivery));
        }
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.deferred, MAX_PENDING_MESSAGES);
        // The overflow suppresses with a seen-id commit instead of
        // accumulating without bound.
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), MAX_PENDING_MESSAGES);
    }

    #[test]
    fn commit_failure_resyncs_uncommitted_views() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];

        // Read-only store: the commit fails after inbox ingest marked
        // the message seen and the log observed it.
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o555))
            .unwrap();
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();
        // Root bypasses permissions, so probe writability now that the
        // store is supposed to be read-only and skip when the commit
        // failure cannot occur.
        let probe = fixture.dir.path.join(".writetest");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).unwrap();
            std::fs::set_permissions(
                fixture.dir.path.join("commits"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
                .unwrap();
            return;
        }
        queue(&mut fixture, mail.clone());
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());

        // Permissions restored: the engine resynced on failure, so the
        // same envelope processes fresh instead of reading stale
        // in-memory dedupe as a duplicate.
        std::fs::set_permissions(
            fixture.dir.path.join("commits"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::set_permissions(&fixture.dir.path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.current(), 1);
    }

    #[test]
    fn malformed_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        // Sealed under a held epoch key, but the wrapped bytes are
        // neither a valid envelope nor openable: deterministic
        // failure, never a hold.
        for (name, wrapped) in [("garbage", vec![0xCC; 48]), ("truncated", vec![0xDD; 7])] {
            let delivery = Message::Capability(CapabilityPayload {
                device,
                epoch: 2,
                wrapped,
            });
            let mail = vec![deliver(&fixture, 2, &delivery)];
            queue(&mut fixture, mail.clone());
            let report = drain(&mut fixture);
            assert_eq!(report.accepted, 1, "{name} suppresses");
            assert_eq!(fixture.engine.pending_count(), 0, "{name} never pends");
            queue(&mut fixture, mail);
            let report = drain(&mut fixture);
            assert_eq!(report.duplicates, 1, "{name} redelivery is a duplicate");
        }
    }

    #[test]
    fn tampered_capability_wrap_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();

        // A well-formed wrap for the engine device, then tampered: the
        // AEAD open fails deterministically.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("admission is valid");
        let secrets = vec![EpochSecret::from_bytes([0x07; 32]); 2];
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            secrets,
        )
        .expect("device is a member");
        let mut wrapped = capability.wrap().expect("wraps").as_bytes().to_vec();
        wrapped[20] ^= 0xFF;
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 2, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    /// The suppression tests need a capability that unwraps cleanly
    /// against the engine device, so the mismatch — not the seal — is
    /// what the intake must catch.
    fn valid_capability_delivery(
        device: DeviceId,
        genesis: &MembershipTransition,
        admission: &MembershipTransition,
    ) -> Message {
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let state = scratch
            .state_of(&admission.transition_id())
            .expect("transition is valid");
        let capability = Capability::mint(
            member_drive(),
            device,
            &state,
            admission.transition_id(),
            2,
            vec![EpochSecret::from_bytes([0x07; 32]); 2],
        )
        .expect("device is a member");
        Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped: capability.wrap().expect("wraps").as_bytes().to_vec(),
        })
    }

    #[test]
    fn mismatched_capability_device_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // The wrap opens for this device; the outer payload claims a
        // different device. The redundant field is authenticated by the
        // control seal, so the disagreement is tampering or a broken
        // sender: suppress without a durable capability fact.
        let Message::Capability(mut payload) =
            valid_capability_delivery(device, &genesis, &admission)
        else {
            panic!("capability delivery");
        };
        payload.device = DeviceId::from_bytes([0x99; 32]);
        let mail = vec![deliver(&fixture, 2, &Message::Capability(payload))];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
        // Redelivery stays a duplicate: the suppression committed.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn mismatched_capability_epoch_suppresses() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![Change::Admit(Admission {
            device,
            encryption_key: encryption_key(&encryption_sk),
        })]);

        // The same wrap delivered under a lying outer epoch. The
        // envelope open already binds payload epoch to envelope epoch,
        // so the lie is sealed at its own claimed epoch (3): the
        // envelope opens cleanly and only the capability-agreement
        // check catches the disagreement with the wrap's coverage.
        let Message::Capability(mut payload) =
            valid_capability_delivery(device, &genesis, &admission)
        else {
            panic!("capability delivery");
        };
        payload.epoch = 3;
        fixture.engine.add_epoch_key(3, control_key(3));
        let mail = vec![deliver(&fixture, 3, &Message::Capability(payload))];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1, "mismatch suppresses, never defers");
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty(), "no capability installs");
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.duplicates, 1);
    }

    #[test]
    fn announcement_bound_to_orphaned_transition_defers() {
        let mut fixture = fixture();
        fixture.engine.add_epoch_key(3, control_key(3));
        let (owner_sk, owner_id) = owner();
        let (outsider_sk, outsider_id) = key(20);
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();

        // Invalid parent (outsider-signed) with a legitimate
        // owner-signed child: the child is orphaned, never canonical.
        let mut bad = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        bad.author = outsider_id;
        sign(&mut bad, &outsider_sk, &member_drive());
        let child = signed(
            3,
            Some(bad.transition_id()),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(3, child.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&bad)),
            deliver(&fixture, 1, &transition_message(&child)),
            deliver(&fixture, 3, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
    }

    #[test]
    fn announcement_bound_to_contested_transition_resolves() {
        let mut fixture = fixture();
        let (owner_sk, owner_id) = owner();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();
        let members = [owner_id];

        // Unresolved fork: both siblings are contested.
        let sibling_a = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &members,
            &members,
            &owner_sk,
            owner_id,
        );
        let mut with_new = vec![owner_id, key(11).1];
        with_new.sort();
        let sibling_b = signed(
            2,
            Some(genesis_id),
            Vec::new(),
            vec![crate::membership::test_util::admit(key(11).1)],
            &with_new,
            &members,
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(2, sibling_a.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&sibling_a)),
            deliver(&fixture, 1, &transition_message(&sibling_b)),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 1);
        assert_eq!(fixture.engine.pending_count(), 1);

        // The resolution names the winner: it canonicalizes, and the
        // held announcement validates in the same pass.
        let resolution = signed(
            3,
            Some(sibling_a.transition_id()),
            vec![sibling_b.transition_id()],
            vec![Change::Rotate],
            &members,
            &members,
            &owner_sk,
            owner_id,
        );
        // Resolution envelope rides any held epoch; its payload has no
        // epoch binding, so epoch 1 suffices.
        let mail = vec![deliver(&fixture, 1, &transition_message(&resolution))];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.announcements.len(), 1);
    }

    #[test]
    fn announcement_bound_to_invalid_transition_suppresses() {
        let mut fixture = fixture();
        fixture.engine.add_epoch_key(5, control_key(5));
        let (owner_sk, owner_id) = owner();
        let (_, genesis) = Builder::genesis(10);
        let genesis_id = genesis.transition_id();

        // Epoch 5 naming an epoch-1 prev: structurally invalid, with a
        // matching announcement epoch so only the status gate fires.
        let bad = signed(
            5,
            Some(genesis_id),
            Vec::new(),
            vec![Change::Rotate],
            &[owner_id],
            &[owner_id],
            &owner_sk,
            owner_id,
        );
        let bound = announcement_for(5, bad.transition_id());
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&bad)),
            deliver(&fixture, 5, &bound),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.deferred, 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.announcements.is_empty());
    }

    #[test]
    fn unauthorized_capability_suppresses_without_pending() {
        let mut fixture = fixture();
        let device = fixture.recipient;
        let encryption_sk = SecretKey::from_slice(&[0xE0; 32]).unwrap();
        let secret = EpochSecret::from_bytes([0x07; 32]);

        // Genesis observed: the engine device is not a member of its
        // state, so a capability naming it is terminally unauthorized.
        let (_, genesis) = Builder::genesis(10);
        let mail = vec![deliver(&fixture, 1, &transition_message(&genesis))];
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).accepted, 1);
        let stranger = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            genesis.transition_id(),
            1,
            vec![secret.clone()],
        )
        .expect("well-formed");
        let wrapped = stranger.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 1,
            wrapped,
        });
        let mail = vec![deliver(&fixture, 1, &delivery)];
        queue(&mut fixture, mail.clone());
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 1);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
        queue(&mut fixture, mail);
        assert_eq!(drain(&mut fixture).duplicates, 1);

        // Stale key: the device is admitted under one encryption key
        // while the capability delivers to another. Unwrap succeeds
        // (it targets the engine's key) but authorization is final.
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = builder.child(vec![crate::membership::test_util::admit(device)]);
        let mut scratch = MembershipLog::new(member_drive());
        scratch.observe(genesis.clone());
        scratch.observe(admission.clone());
        let stale = Capability::new(
            member_drive(),
            device,
            encryption_key(&encryption_sk),
            admission.transition_id(),
            2,
            vec![secret.clone(), secret],
        )
        .expect("well-formed");
        let wrapped = stale.wrap().expect("wraps").as_bytes().to_vec();
        let delivery = Message::Capability(CapabilityPayload {
            device,
            epoch: 2,
            wrapped,
        });
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &delivery),
        ];
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(fixture.engine.pending_count(), 0);
        let facts = fixture.engine.store.load().expect("loads");
        assert!(facts.capabilities.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn commit_failure_resyncs_and_retries() {
        use std::os::unix::fs::PermissionsExt;

        let mut fixture = fixture();
        let device = fixture.recipient;
        let (mut builder, genesis) = Builder::genesis(10);
        let admission = admit_engine(&mut builder, device);
        let bound = announcement_for(2, admission.transition_id());
        let cap = capability_message(
            device,
            admission.transition_id(),
            2,
            vec![
                EpochSecret::from_bytes([0x08; 32]),
                EpochSecret::from_bytes([0x09; 32]),
            ],
        );
        let mail = vec![
            deliver(&fixture, 1, &transition_message(&genesis)),
            deliver(&fixture, 1, &transition_message(&admission)),
            deliver(&fixture, 2, &cap),
            deliver(&fixture, 2, &bound),
        ];
        queue(&mut fixture, mail.clone());

        // Make the store unwritable. Root bypasses permissions, so
        // probe writability after the chmod and skip when the commit
        // failure cannot occur; otherwise assert the failure, restore,
        // and verify redelivery retries cleanly.
        let dir = fixture.dir.path.clone();
        let commits = dir.join("commits");
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
        }
        let probe = dir.join(".writetest");
        if std::fs::File::create(&probe).is_ok() {
            std::fs::remove_file(&probe).unwrap();
            for path in [&dir, &commits] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            return;
        }

        // The first commit fails: the engine resyncs its views and
        // surfaces the error instead of deciding against uncommitted
        // state or wedging the drain. The queue is untouched (the
        // failure is durable-side), so redelivery handles the retry.
        let recipient = fixture.recipient;
        let mut mailbox = MemoryMailbox {
            relay: &mut fixture.relay,
            owner: recipient,
        };
        assert!(fixture.engine.drain(&mut mailbox).is_err());
        for path in [&dir, &commits] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Retry after the outage: the failed drain consumed genesis
        // from the relay, so redeliver the whole batch fresh. Leftover
        // admission commits at once; the orphaned capability and
        // announcement defer until genesis lands, then ride genesis's
        // commit; the redelivered copies deduplicate. Every effect lands
        // durably exactly once.
        queue(&mut fixture, mail);
        let report = drain(&mut fixture);
        assert_eq!(report.accepted, 2);
        assert_eq!(report.deferred, 2);
        assert_eq!(report.duplicates, 3);
        let facts = fixture.engine.store.load().expect("loads");
        assert_eq!(facts.transitions.len(), 2);
        assert_eq!(facts.announcements.len(), 1);
    }
}
