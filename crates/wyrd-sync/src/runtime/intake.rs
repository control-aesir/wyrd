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
