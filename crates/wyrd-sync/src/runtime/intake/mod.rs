//! Control-plane intake and message classification for the runtime engine.

use std::collections::{BTreeMap, HashSet};

use wyrd_format::{DeviceId, MembershipTransition, SnapshotId, TransitionId};
use zeroize::Zeroizing;

use super::engine::{DeferredWait, DrainReport, Engine, EngineError};
use crate::control::{
    verify_announcement, AnnouncementUpdate, CapabilityPayload, ControlError, ControlMessageId,
    IngestReport, Message, SealedControl, SnapshotAnnouncement,
};
use crate::control::{RotationDelivery, RotationIngest, ROTATION_VERSION};
use crate::durable::{AuthorizedCapability, Fact};
use crate::ingest::{check_total_len, check_transition, Limits};
use crate::keys::capability::{CapabilityError, WrappedCapability};
use crate::membership::TransitionStatus;
use crate::transport::mailbox::{open_from_sender, Disposition, Mailbox, MailboxEnvelope};

const MAX_PENDING_MESSAGES: usize = super::engine::MAX_PENDING_MESSAGES;

enum Action {
    Commit(Vec<Fact>),
    /// Deterministic suppression verdict: the message is invalid and
    /// will never become processable. Commits nothing durable — the
    /// verdict is cached memory-only and bounded — so unique invalid
    /// messages cannot grow state. Redelivery revalidates to the same
    /// outcome after eviction or restart.
    Suppress,
    /// Not yet processable, held with the dependency that unblocks it
    /// (see [`DeferredWait`]).
    Defer(DeferredWait),
}

enum Outcome {
    Accepted,
    Duplicate,
    /// Held in the engine's pending map for transition-triggered
    /// re-drive. The relay retains the envelope as the crash backstop
    /// (pending is volatile), so the drain settles `Retry`.
    Deferred,
    /// Shed past the pending bound: the engine holds nothing, so the
    /// drain settles `Retry` and the relay retains the envelope.
    RelayHeld,
    /// Not yet processable (unknown epoch key); the drain settles
    /// `Retry` and the relay retains the envelope.
    Skipped,
    /// Terminal poison (unopenable outer seal, undecodable payload):
    /// the bytes can never become a message, so the drain settles
    /// `Ack` without writing any fact. There is no message id to
    /// record — the bytes never decoded — and nothing legitimate is
    /// lost by consuming them.
    Discarded,
}

pub(super) fn drain(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<DrainReport, EngineError> {
    let mut report = DrainReport::default();
    // Each handover is offered once per pass: a re-offered id ends the
    // pass with the envelope still unacked, so a pass always terminates
    // even when every envelope is retried.
    let mut offered = HashSet::new();
    // A broken mailbox (poisoned lock, exhausted id space) fails the
    // pass as EngineError::Mailbox via the #[from] conversion — the
    // envelopes stay retained for redelivery on the next pass.
    while let Some(delivery) = mailbox.recv()? {
        if !offered.insert(delivery.id()) {
            break;
        }
        let disposition = match accept_envelope(engine, delivery.envelope())? {
            Outcome::Accepted => {
                report.accepted += 1;
                Disposition::Ack
            }
            Outcome::Duplicate => {
                report.duplicates += 1;
                Disposition::Ack
            }
            Outcome::Deferred => {
                report.deferred += 1;
                Disposition::Retry
            }
            Outcome::RelayHeld => {
                report.deferred += 1;
                Disposition::Retry
            }
            Outcome::Skipped => {
                report.skipped += 1;
                Disposition::Retry
            }
            Outcome::Discarded => {
                report.discarded += 1;
                Disposition::Ack
            }
        };
        mailbox.settle(delivery.id(), disposition)?;
    }
    Ok(report)
}

fn accept_envelope(
    engine: &mut Engine,
    envelope: &MailboxEnvelope,
) -> Result<Outcome, EngineError> {
    let bytes = match open_from_sender(&engine.identity_secret, engine.device, envelope) {
        // The outer seal opens with our always-held identity key or
        // never will: an unopenable envelope is terminal poison, not a
        // retryable unknown. Consume it without a fact. Oversize
        // ciphertext/decrypted bytes (`MailboxError::Oversize`) land here
        // too: the mailbox already rejected them before ingest, and the
        // relay retains nothing for an acked handover.
        Ok(bytes) => bytes,
        Err(_) => return Ok(Outcome::Discarded),
    };
    // Rotation deliveries ride their own framing under a distinct
    // version: dispatch on the version byte before either framing
    // decodes, so neither framing can ever misparse the other (a
    // rotation header's ephemeral bytes would otherwise land where the
    // control envelope keeps its kind tag).
    if bytes.first() == Some(&ROTATION_VERSION) {
        return accept_rotation(engine, envelope, &bytes);
    }
    match engine.inbox.ingest(&bytes) {
        // Only a missing epoch key can heal: the bytes are well-formed
        // for our drive and may become openable when the key arrives.
        Err(ControlError::UnknownEpoch(_)) => Ok(Outcome::Skipped),
        // Decode, version, drive, and crypto failures under a held key
        // are terminal: the bytes can never become a processable
        // message. Consume without a fact so poison cannot accumulate
        // in the relay.
        Err(_) => Ok(Outcome::Discarded),
        Ok(IngestReport::Duplicate) => match sealed_id(&bytes) {
            Some(id) => match engine.take_pending(&id) {
                Some(entry) => commit_action(engine, &id, &entry.message, false, Some(entry.wait)),
                None => Ok(Outcome::Duplicate),
            },
            None => Ok(Outcome::Duplicate),
        },
        Ok(IngestReport::Accepted { id, message }) => {
            commit_action(engine, &id, &message, true, None)
        }
    }
}

fn commit_action(
    engine: &mut Engine,
    id: &ControlMessageId,
    message: &Message,
    is_new: bool,
    held: Option<DeferredWait>,
) -> Result<Outcome, EngineError> {
    // Announcements this pass would commit, validated against each other
    // as well as the hydrated projection: a transition landing may flush
    // several pending messages into one commit, and a fork must never
    // reach the fact log merely because two deferrals resolved together.
    let mut staged: BTreeMap<SnapshotId, SnapshotAnnouncement> = BTreeMap::new();
    let mut facts = match message_action(engine, id, message, &mut staged) {
        Ok(Action::Commit(facts)) => facts,
        Ok(Action::Suppress) => {
            engine.inbox.suppress(id);
            return Ok(Outcome::Accepted);
        }
        Ok(Action::Defer(_)) if engine.pending.len() >= MAX_PENDING_MESSAGES => {
            // Shed without consuming: the bound protects memory, but a
            // resource decision must never write a semantic fact. The
            // relay retains the envelope (the drain settles `Retry`),
            // and the inbox forgets the id so the redelivery ingests
            // fresh instead of reporting a false duplicate. No durable
            // fact is written for a message never processed.
            engine.inbox.forget(id);
            return Ok(Outcome::RelayHeld);
        }
        Ok(Action::Defer(wait)) => {
            engine.hold_pending(*id, message.clone(), wait);
            return Ok(Outcome::Deferred);
        }
        Err(error) => {
            // The pass fails after volatile writes: the transition (if
            // any) is observed in the log, but no fact committed. A
            // message taken from pending on redelivery is re-held under
            // its previous dependency so its slot survives; a fresh
            // message rides relay redelivery (its handover was never
            // settled). Either way resync drops the uncommitted
            // observations and suppress verdicts, restoring the durable
            // baseline before the error surfaces.
            if let Some(wait) = held {
                engine.hold_pending(*id, message.clone(), wait);
            }
            let _ = engine.resync();
            return Err(error);
        }
    };
    if !is_new {
        facts.clear();
        staged.clear();
    }
    if matches!(message, Message::MembershipTransition(_)) {
        // A newly committed transition flushes the volatile pending
        // entries waiting on it — whether the transition arrived
        // epoch-sealed or carried by a rotation delivery. Entries held
        // on other unseen transitions stay parked without re-drive.
        let committed = committed_transition(message);
        match flush_pending(engine, &mut staged, committed) {
            Ok(more) => facts.extend(more),
            Err(error) => {
                let _ = engine.resync();
                return Err(error);
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
    note_committed_facts(engine, &facts);
    // The projection follows the durable state, never leads it: staged
    // announcements merge only after the fact batch committed.
    for (snapshot, announcement) in std::mem::take(&mut staged) {
        engine.announcements.insert(snapshot, announcement);
    }
    Ok(Outcome::Accepted)
}

/// The transition id a committed [`Message::MembershipTransition`]
/// carries. `message_action` decoded the same bytes above, so `None`
/// is unreachable through the intake paths; callers fall back to
/// waking every held entry rather than stranding one on a decoding
/// disagreement.
fn committed_transition(message: &Message) -> Option<TransitionId> {
    let Message::MembershipTransition(payload) = message else {
        return None;
    };
    MembershipTransition::from_canonical_bytes(&payload.transition)
        .ok()
        .map(|transition| transition.transition_id())
}

/// Walk the volatile pending queue in arrival order (see
/// `Engine::hold_pending`), re-driving the entries the newly
/// committed transition unblocks: entries held on its id, plus every
/// status-blocked entry (their standing reads the global membership
/// analysis, so any commit can change it). Entries held on other
/// unseen transitions stay parked — their awaited id is still
/// unobserved, so re-driving them could change nothing. Staged
/// announcement compatibility and the durable fact order stay
/// deterministic over the woken prefix. Shared by the transition arm
/// and the rotation path — a newly observed transition flushes pending
/// no matter which framing carried it.
///
/// On failure the in-flight message and the unprocessed remainder are
/// restored in arrival order (every id here is disjoint from the
/// re-held ones, so `hold_pending` appends without clobbering) and the
/// error returns for the caller to resync: suppressed and
/// fact-consumed prefixes redeliver via the relay (never settled), and
/// the observations and verdicts they left behind go away with the
/// caller's resync, which must run after the restore — resync rebuilds
/// from durable facts and never touches the volatile queue.
fn flush_pending(
    engine: &mut Engine,
    staged: &mut BTreeMap<SnapshotId, SnapshotAnnouncement>,
    committed: Option<TransitionId>,
) -> Result<Vec<Fact>, EngineError> {
    let taken = std::mem::take(&mut engine.pending);
    let mut facts = Vec::new();
    let mut failed_at: Option<(usize, EngineError)> = None;
    for (index, entry) in taken.iter().enumerate() {
        // Parked on another unseen transition: the commit cannot have
        // unblocked it — hold it back without re-drive.
        if committed.is_some_and(|id| !entry.wait.wake_on(&id)) {
            engine.hold_pending(entry.id, entry.message.clone(), entry.wait);
            continue;
        }
        match message_action(engine, &entry.id, &entry.message, staged) {
            Ok(Action::Commit(more)) => facts.extend(more),
            Ok(Action::Suppress) => {
                engine.inbox.suppress(&entry.id);
            }
            Ok(Action::Defer(wait)) => {
                engine.hold_pending(entry.id, entry.message.clone(), wait);
            }
            Err(error) => {
                failed_at = Some((index, error));
                break;
            }
        }
    }
    if let Some((index, error)) = failed_at {
        for entry in taken.into_iter().skip(index) {
            engine.hold_pending(entry.id, entry.message, entry.wait);
        }
        return Err(error);
    }
    Ok(facts)
}

/// Mirror a committed fact batch into the volatile engine state: the
/// inbox remembers durably-seen ids (ingest-time marking covers the
/// normal flow, but a resync later in the same drain rebuilds the inbox
/// from durable facts — without this, redelivery would report fresh
/// and commit the same facts twice), and newly authorized epoch
/// material installs its control keys where none is held, so a device
/// that just received epoch N's capability opens epoch-N control
/// traffic on the next envelope instead of stalling it as skipped.
/// Fill-vacant only, matching the keyring's first-wins install: a held
/// key is never replaced behind the traffic sealed under it, and
/// conflicting epoch secrets stay the keyring's fail-closed
/// `EpochConflict`, not a silent key swap. The grant was authorized
/// above; only decryption keys derive here, and every message they open
/// is still independently verified.
fn note_committed_facts(engine: &mut Engine, facts: &[Fact]) {
    for fact in facts {
        if let Fact::ControlMessage(id) = fact {
            engine.inbox.remember(id);
        }
        if let Fact::Capability(authorized) = fact {
            let drive = engine.drive;
            for (index, secret) in authorized.capability().secrets.iter().enumerate() {
                let epoch = index as u64 + 1;
                if !engine.epoch_keys.contains_key(&epoch) {
                    engine.add_epoch_key(epoch, Zeroizing::new(secret.control_key(&drive, epoch)));
                }
            }
        }
    }
}

fn message_action(
    engine: &mut Engine,
    id: &ControlMessageId,
    message: &Message,
    staged: &mut BTreeMap<SnapshotId, SnapshotAnnouncement>,
) -> Result<Action, EngineError> {
    match message {
        Message::MembershipTransition(payload) => {
            if check_total_len(&Limits::V0, "transition", payload.transition.len()).is_err() {
                return Ok(Action::Suppress);
            }
            let transition = match MembershipTransition::from_canonical_bytes(&payload.transition) {
                Ok(transition) => transition,
                Err(_) => return Ok(Action::Suppress),
            };
            if check_transition(&Limits::V0, &transition).is_err() {
                return Ok(Action::Suppress);
            }
            engine.log.observe(transition.clone());
            Ok(Action::Commit(vec![
                Fact::Transition(transition),
                Fact::ControlMessage(*id),
            ]))
        }
        Message::SnapshotAnnouncement(announcement) => {
            // Authorship first: an announcement is evidence only when
            // the author's signature verifies against the drive-bound
            // challenge. A bad signature is malformed evidence like an
            // unparsable transition — suppress memory-only, never
            // defer.
            if verify_announcement(&engine.drive(), announcement).is_err() {
                return Ok(Action::Suppress);
            }
            match engine.log.transition(&announcement.membership) {
                // Unseen: only the arrival of this transition unblocks.
                None => Ok(Action::Defer(DeferredWait::Unseen(announcement.membership))),
                Some(t) if t.epoch != announcement.epoch => Ok(Action::Suppress),
                Some(_) => match engine.log.status(&announcement.membership) {
                    Some(TransitionStatus::Canonical) => {
                        // The compatibility gate: an announcement becomes a
                        // durable fact only when it is compatible with the
                        // announcement already known for the snapshot — the
                        // hydrated projection, or an announcement staged
                        // earlier in this commit batch. Route updates
                        // (mutable `node_addr` only) commit a fresh fact;
                        // the last accepted route wins. An immutable fork is
                        // the sender's invalid data: the verdict is final
                        // but memory-only, and no announcement fact is
                        // written, so replay never meets a conflict intake
                        // could have detected.
                        let known = engine
                            .announcements
                            .get(&announcement.snapshot)
                            .or_else(|| staged.get(&announcement.snapshot));
                        let committable = match known {
                            None => true,
                            Some(existing) => !matches!(
                                existing.check_update(announcement),
                                AnnouncementUpdate::Fork
                            ),
                        };
                        if committable {
                            staged.insert(announcement.snapshot, announcement.clone());
                            Ok(Action::Commit(vec![
                                Fact::Announcement(announcement.clone()),
                                Fact::ControlMessage(*id),
                            ]))
                        } else {
                            Ok(Action::Suppress)
                        }
                    }
                    Some(TransitionStatus::Invalid(_)) => Ok(Action::Suppress),
                    Some(
                        TransitionStatus::Contested
                        | TransitionStatus::Voided
                        | TransitionStatus::Orphaned
                        | TransitionStatus::Pending,
                    ) => Ok(Action::Defer(DeferredWait::StatusBlocked(
                        announcement.membership,
                    ))),
                    // Observed a moment ago via transition(), but the
                    // fresh analysis classifies nothing for it: an
                    // internal disagreement, not sender data. Fail the
                    // pass — the envelope stays retained for redelivery.
                    // Unreachable through the public log API (both views
                    // read the same observed set); defense in depth for a
                    // future analysis that can miss, mirroring the
                    // mailbox ceiling gates.
                    None => Err(EngineError::TransitionUnclassified(announcement.membership)),
                },
            }
        }
        // Envelope-defined but unhandled in v0: no rotation handler
        // exists, so rotation messages are terminal no-ops —
        // acknowledged and discarded, never deferred (deferral would
        // park poison for retry). When rotation handling lands this arm
        // becomes a commit or a deferral; until then no durable record
        // distinguishes consumed from never-recorded (see trust.md).
        Message::KeyRotation(_) => Ok(Action::Suppress),
        Message::Capability(payload) => Ok(capability_action(engine, id, payload)),
    }
}

fn capability_action(
    engine: &Engine,
    id: &ControlMessageId,
    payload: &CapabilityPayload,
) -> Action {
    let capability = match WrappedCapability::from_bytes(payload.wrapped.clone())
        .unwrap(&engine.encryption_secret)
    {
        Ok(capability) => capability,
        Err(_) => return Action::Suppress,
    };
    // Redundant-field agreement, mirrored from the control envelope
    // (T15): the sealed payload's device and epoch are authenticated
    // delivery metadata and must match the capability they deliver. A
    // disagreement is tampering or a broken sender — it never heals by
    // deferring, so suppress memory-only.
    if payload.device != capability.device || payload.epoch != capability.covered_epoch() {
        return Action::Suppress;
    }
    // One authoritative lookup inside authorize: the transition and
    // the state it produces are inseparable, so the capability is
    // checked against exactly its own authorizing history. Unobserved
    // or pending transitions defer — the history may still arrive or
    // resolve; terminally invalid or orphaned history, and every other
    // authorization failure, suppress without a durable capability
    // fact, so poison is never parked for retry.
    let transition_id = capability.transition;
    match AuthorizedCapability::authorize(capability, engine.drive(), &engine.log, &transition_id) {
        Ok(authorized) => Action::Commit(vec![
            Fact::Capability(authorized),
            Fact::ControlMessage(*id),
        ]),
        // Unseen or gap-pending history may still arrive or resolve:
        // hold on the transition with the matching wake rule (exact
        // for unseen, every-commit for observed-but-blocked).
        Err(CapabilityError::UnknownTransition(waited)) => {
            if engine.log.contains(&waited) {
                Action::Defer(DeferredWait::StatusBlocked(waited))
            } else {
                Action::Defer(DeferredWait::Unseen(waited))
            }
        }
        Err(_) => Action::Suppress,
    }
}

fn sealed_id(bytes: &[u8]) -> Option<ControlMessageId> {
    SealedControl::decode(bytes)
        .ok()
        .map(|sealed| sealed.message_id())
}

/// Accept a rotation delivery: epoch-key delivery for a device holding
/// no later epoch secret. The dispatch in [`accept_envelope`] routes
/// here on the version byte, after the outer mailbox seal opened — the
/// sender below is therefore authenticated transport metadata, not a
/// claim.
///
/// Sender authorization is single-predicate, because the ECDH seal
/// proves nothing about the sender (anyone can seal to a public key):
/// `rotation_commit` admits the delivery only from a member of the
/// epoch it grants, and deliberately not from a member of the
/// receiver's current tip — a delayed delivery from a since-removed
/// member must still converge, so convergence never depends on
/// arrival timing. A mint for an epoch the sender does not hold cannot
/// bind the epoch's transition id — the id is unknowable without
/// opening the epoch's traffic — and holders are already trusted with
/// the secrets they hold, so member-sendership is exactly the epoch
/// seal's old possession proof, restated.
fn accept_rotation(
    engine: &mut Engine,
    envelope: &MailboxEnvelope,
    bytes: &[u8],
) -> Result<Outcome, EngineError> {
    // No tip-based sender pre-check here, deliberately: a delivery
    // authored by a member of epoch N may arrive after the receiver
    // learns a later removal of that sender, and rejecting on the
    // current tip would make convergence depend on arrival timing
    // (discarding the only retained grant). Sender authorization
    // belongs to `rotation_commit`, against the authorizing state —
    // the single predicate that cannot mistime. Outsider spam pays
    // one ECDH open before the authoritative check suppresses it,
    // the same shape as any other poison.
    let sender = envelope.sender;
    match engine
        .inbox
        .ingest_rotation(bytes, &engine.encryption_secret)
    {
        // Decode, version, drive, and crypto failures are terminal: the
        // bytes can never become a processable delivery. Consume
        // without a fact so poison cannot accumulate in the relay.
        Err(_) => Ok(Outcome::Discarded),
        // Rotation deliveries never enter the volatile pending queue
        // (unprocessable ones skip for relay redelivery instead), so a
        // duplicate has nothing to re-drive.
        Ok(RotationIngest::Duplicate) => Ok(Outcome::Duplicate),
        Ok(RotationIngest::Accepted { id, delivery }) => {
            rotation_commit(engine, &id, sender, &delivery)
        }
    }
}

/// Commit an opened rotation delivery: unwrap, verify every binding,
/// observe the carried transition, authorize the capability, and commit
/// the transition, the grant, and the delivery id atomically — then
/// flush volatile pending and fill control keys like any commit.
/// Almost every failure below is deterministic-invalid (wrong device,
/// unopenable wrap, binding mismatch, terminal history, non-member
/// sender): suppress memory-only, never defer. The two healable cases
/// skip for relay redelivery instead: an unobserved ancestry gap
/// (the history may still arrive) and a missing tip (the log may still
/// advance). Post-commit failures resync like every other commit path.
fn rotation_commit(
    engine: &mut Engine,
    id: &ControlMessageId,
    sender: DeviceId,
    delivery: &RotationDelivery,
) -> Result<Outcome, EngineError> {
    let suppress = |engine: &mut Engine| {
        engine.inbox.suppress(id);
        Ok(Outcome::Accepted)
    };
    // Not for us: the mailbox routes by recipient, so a mismatch is a
    // broken sender — terminal, never healed by redelivery.
    if delivery.device != engine.device {
        return suppress(engine);
    }
    let capability = match WrappedCapability::from_bytes(delivery.wrapped.clone())
        .unwrap(&engine.encryption_secret)
    {
        Ok(capability) => capability,
        Err(_) => return suppress(engine),
    };
    // Redundant-field agreement, mirrored from the capability arm: the
    // delivery metadata and the capability it carries must name this
    // device and epoch. Anyone can seal to our public key, so the wrap
    // alone cannot prove address — the check happens here, before
    // anything commits, and a mismatch never heals by deferring.
    if capability.device != engine.device || delivery.epoch != capability.covered_epoch() {
        return suppress(engine);
    }
    let transition = match MembershipTransition::from_canonical_bytes(&delivery.transition) {
        Ok(transition) => transition,
        Err(_) => return suppress(engine),
    };
    // The carried transition must be the capability's own binding, at
    // the delivery's epoch, within ingest limits — a transition for
    // another epoch or binding paired with this wrap is tampering or a
    // broken sender, never a gap that fills.
    if transition.transition_id() != capability.transition
        || transition.epoch != delivery.epoch
        || check_total_len(&Limits::V0, "transition", delivery.transition.len()).is_err()
        || check_transition(&Limits::V0, &transition).is_err()
    {
        return suppress(engine);
    }
    let transition_id = transition.transition_id();
    // Authorize against a scratch observation: the live log stays
    // pristine until commit, so a skip leaves no volatile-only
    // observation behind — volatile matches durable on every path,
    // and a redelivery revalidates against the same baseline. The
    // scratch set equals the live set plus this transition, and
    // nothing mutates the live log between the clone and the real
    // observe below, so the verdicts transfer exactly.
    let mut scratch = engine.log.clone();
    scratch.observe(transition.clone());
    let authorized =
        match AuthorizedCapability::authorize(capability, engine.drive(), &scratch, &transition_id)
        {
            Ok(authorized) => authorized,
            // The ancestry gap may still fill (out-of-order rotation
            // converges on redelivery): forget the ingest marking so the
            // retained envelope ingests fresh instead of reporting a false
            // duplicate, and leave it to the relay.
            Err(CapabilityError::UnknownTransition(_)) => {
                engine.inbox.forget(id);
                return Ok(Outcome::Skipped);
            }
            Err(_) => return suppress(engine),
        };
    // Sender-member, against the authorizing state (not the tip): the
    // delivery is authorized only from a member of the epoch it grants.
    // A former member removed by this very history cannot speak its
    // secrets; the owner never leaves the member set short of the
    // terminal state, so genuine senders always pass.
    match scratch.members_of(&transition_id) {
        Some(members) if members.contains(&sender) => {}
        Some(_) => return suppress(engine),
        // Observed a moment ago, but the fresh analysis derives no
        // state for it: the same internal disagreement the
        // announcement arm fails loudly on, not sender data.
        None => return Err(EngineError::TransitionUnclassified(transition_id)),
    }
    engine.log.observe(transition.clone());
    let mut staged: BTreeMap<SnapshotId, SnapshotAnnouncement> = BTreeMap::new();
    let mut facts = vec![
        Fact::Transition(transition),
        Fact::Capability(authorized),
        Fact::ControlMessage(*id),
    ];
    match flush_pending(engine, &mut staged, Some(transition_id)) {
        Ok(more) => facts.extend(more),
        Err(error) => {
            let _ = engine.resync();
            return Err(error);
        }
    }
    if let Err(error) = engine.commit_facts(&facts) {
        let _ = engine.resync();
        return Err(error.into());
    }
    note_committed_facts(engine, &facts);
    // Staged announcements merge only after the fact batch committed,
    // mirroring the projection discipline of the control path.
    for (snapshot, announcement) in std::mem::take(&mut staged) {
        engine.announcements.insert(snapshot, announcement);
    }
    Ok(Outcome::Accepted)
}

// Intake behavior tests live beside the drain pipeline, one file per
// theme: the commit pipeline, capability validation, announcement
// binding, rotation delivery, and backpressure/commit recovery.
#[cfg(test)]
mod tests_announcement;
#[cfg(test)]
mod tests_capability;
#[cfg(test)]
mod tests_deferred;
#[cfg(test)]
mod tests_harness;
#[cfg(test)]
mod tests_pipeline;
#[cfg(test)]
mod tests_resilience;
#[cfg(test)]
mod tests_rotation;
