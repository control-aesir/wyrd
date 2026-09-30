//! Control-plane intake and message classification for the runtime engine.

use std::collections::{BTreeMap, HashMap, HashSet};

use wyrd_format::{DeviceId, MembershipTransition, SnapshotId, TransitionId};
use zeroize::Zeroizing;

use super::engine::{DeferredWait, DrainReport, Engine, EngineError, PendingEntry};
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

/// Max facts committed per drain pass, across all senders: past this
/// many, committable envelopes shed relay-held for the next pass. The
/// relay retains everything, so deferral is the same safe backpressure
/// shape as the pending bound — paced, never dropped. Counts facts,
/// not envelopes: the abuse being bounded is fact-log growth (disk and
/// restart/replay cost), and one envelope can flush a parked batch on
/// top of its own facts.
const MAX_INTAKE_COMMITS_PER_PASS: usize = 1024;

/// Max facts one sender's envelopes may commit per drain pass: past
/// this many, that sender's further committable envelopes shed
/// relay-held while other senders still admit, so one device cannot
/// consume the whole pass budget. Keyed by the mailbox sender, which
/// is authenticated transport metadata, not a message claim.
const MAX_INTAKE_COMMITS_PER_SENDER_PER_PASS: usize = 256;

/// The per-pass intake commit budget: committed facts total plus per
/// mailbox-sender committed facts. Pass-local (created fresh per
/// drain): a shed envelope's redelivery re-admits against the next
/// pass's empty budget, so pacing converges without any carried
/// state. Flushed parked entries charge the triggering sender — their
/// own sender is not recorded on the pending entry, and the trigger
/// is what chose to unblock them this pass.
#[derive(Debug, Default)]
struct IntakeBudget {
    commits: usize,
    per_sender: HashMap<DeviceId, usize>,
}

impl IntakeBudget {
    /// Charge `facts` against the budget, or refuse when either
    /// the pass budget or the sender quota would overflow. A zero
    /// charge always admits (duplicate and suppression paths carry no
    /// facts, and must never trip the bound).
    fn admit(&mut self, sender: DeviceId, facts: usize) -> bool {
        if !self.would_admit(sender, facts) {
            return false;
        }
        self.commits += facts;
        *self.per_sender.entry(sender).or_insert(0) += facts;
        true
    }

    /// Whether `admit` would succeed, without charging: the
    /// classification arms shed over-budget messages before spending
    /// verification or mutating any view, so a shed leaves the log,
    /// the projection, and the pending queue exactly as found.
    fn would_admit(&self, sender: DeviceId, facts: usize) -> bool {
        if self.commits + facts > MAX_INTAKE_COMMITS_PER_PASS {
            return false;
        }
        self.per_sender.get(&sender).unwrap_or(&0) + facts <= MAX_INTAKE_COMMITS_PER_SENDER_PER_PASS
    }
}

#[derive(Debug)]
enum Action {
    Commit(Vec<Fact>),
    /// Already recorded: a byte-identical announcement, or a
    /// transition already in the observed set (the transition id
    /// covers every byte, so same id means same document). Commits
    /// nothing — a fresh seal over equivalent payload buys no new
    /// durable fact — and acks, so the relay drops the envelope.
    /// Restart-safe: redelivery re-derives the same verdict from
    /// durable state.
    Duplicate,
    /// Over the pass commit budget or the sender quota: the envelope
    /// sheds relay-held for the next pass, like the pending-overflow
    /// shed. Unlike `Defer`, nothing parks in the pending queue —
    /// redelivery revalidates from scratch against a fresh budget.
    /// Decided before any verification or view mutation, so a shed
    /// leaves the log, the projection, and the queue untouched.
    Shed,
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

#[derive(Debug)]
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
    /// `Poison` without writing any fact: the relay may discard the
    /// envelope, and the mailbox records it memory-only. There is no
    /// message id to record — the bytes never decoded — and nothing
    /// legitimate is lost by consuming them.
    Discarded,
}

pub(super) fn drain(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<DrainReport, EngineError> {
    let mut report = DrainReport::default();
    let mut budget = IntakeBudget::default();
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
        let disposition = match accept_envelope(engine, delivery.envelope(), &mut budget)? {
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
                Disposition::Poison
            }
        };
        mailbox.settle(delivery.id(), disposition)?;
    }
    Ok(report)
}

fn accept_envelope(
    engine: &mut Engine,
    envelope: &MailboxEnvelope,
    budget: &mut IntakeBudget,
) -> Result<Outcome, EngineError> {
    let bytes = match open_from_sender(&engine.identity_secret, engine.device, envelope) {
        // The outer seal opens with our always-held identity key or
        // never will: an unopenable envelope is terminal poison, not a
        // retryable unknown. Consume it without a fact. Oversize
        // ciphertext/decrypted bytes (`MailboxError::Oversize`) land here
        // too: the mailbox already rejected them before ingest, and the
        // relay retains nothing for a settled handover.
        Ok(bytes) => bytes,
        Err(error) => {
            // Per-envelope forensics: a stuck peer shows identical
            // silence for poison, missing keys, and deferral — the
            // verdict line names which one each delivery met.
            tracing::debug!(outcome = "discarded", reason = %error, "intake verdict");
            return Ok(Outcome::Discarded);
        }
    };
    // Rotation deliveries ride their own framing under a distinct
    // version: dispatch on the version byte before either framing
    // decodes, so neither framing can ever misparse the other (a
    // rotation header's ephemeral bytes would otherwise land where the
    // control envelope keeps its kind tag).
    if bytes.first() == Some(&ROTATION_VERSION) {
        let outcome = accept_rotation(engine, envelope, &bytes, budget)?;
        tracing::debug!(kind = "rotation-delivery", outcome = ?outcome, "intake verdict");
        return Ok(outcome);
    }
    match engine.inbox.ingest(&bytes) {
        // Only a missing epoch key can heal: the bytes are well-formed
        // for our drive and may become openable when the key arrives.
        Err(ControlError::UnknownEpoch(epoch)) => {
            tracing::debug!(outcome = "skipped", epoch, "intake verdict");
            Ok(Outcome::Skipped)
        }
        // Decode, version, drive, and crypto failures under a held key
        // are terminal: the bytes can never become a processable
        // message. Consume without a fact so poison cannot accumulate
        // in the relay.
        Err(error) => {
            tracing::debug!(outcome = "discarded", reason = %error, "intake verdict");
            Ok(Outcome::Discarded)
        }
        Ok(IngestReport::Duplicate) => match sealed_id(&bytes) {
            Some(id) => match engine.take_pending(&id) {
                Some(entry) => commit_action(
                    engine,
                    envelope.sender,
                    &id,
                    &entry.message,
                    false,
                    Some(entry.wait),
                    budget,
                ),
                None => Ok(Outcome::Duplicate),
            },
            None => Ok(Outcome::Duplicate),
        },
        Ok(IngestReport::Accepted { id, message }) => {
            commit_action(engine, envelope.sender, &id, &message, true, None, budget)
        }
    }
}

fn commit_action(
    engine: &mut Engine,
    sender: DeviceId,
    id: &ControlMessageId,
    message: &Message,
    is_new: bool,
    held: Option<DeferredWait>,
    budget: &mut IntakeBudget,
) -> Result<Outcome, EngineError> {
    // Announcements this pass would commit, validated against each other
    // as well as the hydrated projection: a transition landing may flush
    // several pending messages into one commit, and a fork must never
    // reach the fact log merely because two deferrals resolved together.
    let mut staged: BTreeMap<SnapshotId, SnapshotAnnouncement> = BTreeMap::new();
    let action = message_action(engine, id, message, &mut staged, sender, budget);
    tracing::debug!(kind = ?message.kind(), id = ?id, action = ?action, "intake verdict");
    let mut facts = match action {
        Ok(Action::Commit(facts)) => facts,
        Ok(Action::Duplicate) => return Ok(Outcome::Duplicate),
        Ok(Action::Shed) => {
            // Shed before any view mutated: forget the ingest marking
            // so redelivery ingests fresh, and leave the envelope to
            // the relay. The per-pass budget is the only state the
            // shed consulted, and it resets every pass.
            engine.inbox.forget(id);
            return Ok(Outcome::RelayHeld);
        }
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
        // A redelivered pending-taken message revalidates but never
        // re-commits: its facts were either committed by the pass that
        // took it or shed back to the relay, and either way this
        // envelope carries nothing new.
        return Ok(Outcome::Duplicate);
    }
    if facts.is_empty() {
        return Ok(Outcome::Duplicate);
    }
    // Charge the envelope's own facts before the flush can mutate
    // the pending queue: the classification already shed over-budget
    // messages above (so this always admits — it is the charge, not
    // the decision), and the flush paces its own batches below.
    // Past this point the envelope commits. The debug assert keeps
    // that ordering claim machine-checked: every Commit arm returns
    // exactly the facts it pre-checked, so admitting here cannot fail
    // after message_action already observed and staged.
    debug_assert!(budget.would_admit(sender, facts.len()));
    if !budget.admit(sender, facts.len()) {
        engine.inbox.forget(id);
        return Ok(Outcome::RelayHeld);
    }
    if matches!(message, Message::MembershipTransition(_)) {
        // A newly committed transition flushes the volatile pending
        // entries waiting on it — whether the transition arrived
        // epoch-sealed or carried by a rotation delivery. Entries held
        // on other unseen transitions stay parked without re-drive.
        let committed = committed_transition(message);
        match flush_pending(engine, &mut staged, committed, sender, budget) {
            Ok(more) => facts.extend(more),
            Err(error) => {
                let _ = engine.resync();
                return Err(error);
            }
        }
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

/// Re-drive the pending entries the newly committed transition
/// unblocks, in arrival order (see [`PendingQueue::wake_seqs`]):
/// entries held on its id, plus every status-blocked entry (their
/// standing reads the global membership analysis, so any commit can
/// change it). Entries held on other unseen transitions are never
/// visited — neither traversed nor cloned — so flush work stays
/// proportional to the woken set, never the parked queue. Staged
/// announcement compatibility and the durable fact order stay
/// deterministic over the woken order. Shared by the transition arm
/// and the rotation path — a newly observed transition flushes pending
/// no matter which framing carried it.
///
/// Each entry leaves the queue before it re-drives and returns to its
/// original slot when it defers again, so arrival order never shifts
/// under a commit that does not consume the entry. On failure the
/// failed entry is restored to its slot and the error returns for the
/// caller to resync: entries already consumed redeliver via the relay
/// (never settled), entries never visited are untouched, and the
/// observations and verdicts left behind go away with the caller's
/// resync, which must run after the restore — resync rebuilds from
/// durable facts and never touches the volatile queue.
///
/// The flush paces itself against the pass budget: an entry whose
/// facts would overflow the budget (or the triggering sender's quota)
/// is restored to its slot and the flush stops, leaving the rest
/// parked for the next pass. Unvisited entries are never removed, so
/// stopping early loses nothing — the relay still holds every parked
/// envelope, and the next commit re-wakes them.
fn flush_pending(
    engine: &mut Engine,
    staged: &mut BTreeMap<SnapshotId, SnapshotAnnouncement>,
    committed: Option<TransitionId>,
    sender: DeviceId,
    budget: &mut IntakeBudget,
) -> Result<Vec<Fact>, EngineError> {
    // Snapshot the wake set up front: the index, not a full queue
    // walk. Later re-drives in this loop only reinsert, never remove
    // unvisited entries, so these sequences stay valid throughout.
    let wake = engine.pending.wake_seqs(committed);
    let mut facts = Vec::new();
    for seq in wake {
        let Some(entry) = engine.pending.remove_seq(seq) else {
            continue;
        };
        match message_action(engine, &entry.id, &entry.message, staged, sender, budget) {
            Ok(Action::Commit(more)) => {
                if budget.admit(sender, more.len()) {
                    facts.extend(more);
                } else {
                    engine.pending.restore(seq, entry);
                    break;
                }
            }
            Ok(Action::Duplicate) => {
                // Already recorded: the entry is consumed, like a
                // committed one, but contributes no facts.
            }
            Ok(Action::Shed) => {
                // Over budget mid-flush: the entry returns to its
                // slot and the rest stay parked for the next pass.
                engine.pending.restore(seq, entry);
                break;
            }
            Ok(Action::Suppress) => {
                engine.inbox.suppress(&entry.id);
            }
            Ok(Action::Defer(wait)) => {
                let id = entry.id;
                let message = entry.message;
                engine
                    .pending
                    .restore(seq, PendingEntry { id, message, wait });
            }
            Err(error) => {
                engine.pending.restore(seq, entry);
                return Err(error);
            }
        }
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
    sender: DeviceId,
    budget: &mut IntakeBudget,
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
            // Already recorded: the transition id covers every byte,
            // so an observed id means this exact document committed —
            // a reseal under a fresh message id buys no new fact.
            if engine.log.contains(&transition.transition_id()) {
                return Ok(Action::Duplicate);
            }
            if check_transition(&Limits::V0, &transition).is_err() {
                return Ok(Action::Suppress);
            }
            // Shed before observing: an observation without a commit
            // would validate later envelopes against uncommitted
            // state for the rest of the pass.
            if !budget.would_admit(sender, 2) {
                return Ok(Action::Shed);
            }
            engine.log.observe(transition.clone());
            Ok(Action::Commit(vec![
                Fact::Transition(transition),
                Fact::ControlMessage(*id),
            ]))
        }
        Message::SnapshotAnnouncement(announcement) => {
            // Cheap rejection first: the membership lookup, the epoch
            // agreement, and the standing read are hash-map work,
            // while the signature verify below is curve work. An
            // announcement for an unseen transition defers (only that
            // transition's arrival unblocks it) and an epoch-mismatched
            // one suppresses — both without spending verification on
            // bytes that cannot commit yet. Verification still gates
            // every commit: a deferred message revalidates fully when
            // flushed, so a bad signature only buys a bounded pending
            // slot, never a fact.
            match engine.log.transition(&announcement.membership) {
                // Unseen: only the arrival of this transition unblocks.
                None => Ok(Action::Defer(DeferredWait::Unseen(announcement.membership))),
                Some(t) if t.epoch != announcement.epoch => Ok(Action::Suppress),
                Some(_) => {
                    match engine.log.status(&announcement.membership) {
                        Some(TransitionStatus::Canonical) => {
                            // Authorship role: readers hold epoch secrets and
                            // materialize, but author nothing (epochs.md). A
                            // reader-signed announcement is structurally valid
                            // yet unauthorized at the bound transition — the
                            // body classifier would reject it later, so admit
                            // no announcement fact, queue no fetch, and keep
                            // the verdict memory-only and bounded like other
                            // poison. Strangers still commit for the body
                            // phase to judge; only the known-voiceless role
                            // suppresses here. The missing-state miss falls
                            // through deliberately: inside the Canonical arm
                            // the derived state exists by construction, and
                            // `authoritative` clones the same state this
                            // read clones — no fail-open is reachable.
                            if engine
                                .log
                                .readers_of(&announcement.membership)
                                .is_some_and(|readers| readers.contains(&announcement.author))
                            {
                                return Ok(Action::Suppress);
                            }
                            // The compatibility gate: an announcement becomes a
                            // durable fact only when it is compatible with the
                            // announcement already known for the snapshot — the
                            // hydrated projection, or an announcement staged
                            // earlier in this commit batch. Route updates
                            // (mutable `node_addr` only) commit a fresh fact;
                            // the last accepted route wins. A byte-identical
                            // replay is already recorded and acks free: the
                            // check needs no budget because the verdict
                            // commits nothing. An immutable fork is the
                            // sender's invalid data: the verdict is final
                            // but memory-only, and no announcement fact is
                            // written, so replay never meets a conflict intake
                            // could have detected.
                            let known = engine
                                .announcements
                                .get(&announcement.snapshot)
                                .or_else(|| staged.get(&announcement.snapshot));
                            let update = known.map(|existing| existing.check_update(announcement));
                            if update == Some(AnnouncementUpdate::Same) {
                                return Ok(Action::Duplicate);
                            }
                            // Shed before spending verification: an
                            // over-budget envelope revalidates against the
                            // next pass's fresh budget instead of burning
                            // curve work this pass.
                            if !budget.would_admit(sender, 2) {
                                return Ok(Action::Shed);
                            }
                            // Authorship: an announcement is evidence only when
                            // the author's signature verifies against the
                            // drive-bound challenge. A bad signature is
                            // malformed evidence like an unparsable
                            // transition — suppress memory-only, never defer.
                            if verify_announcement(&engine.drive(), announcement).is_err() {
                                return Ok(Action::Suppress);
                            }
                            match update {
                                None | Some(AnnouncementUpdate::RouteUpdate) => {
                                    staged.insert(announcement.snapshot, announcement.clone());
                                    Ok(Action::Commit(vec![
                                        Fact::Announcement(announcement.clone()),
                                        Fact::ControlMessage(*id),
                                    ]))
                                }
                                // Decided above; unreachable here, kept so
                                // the gate stays exhaustive over the
                                // reannouncement cases.
                                Some(AnnouncementUpdate::Same) => Ok(Action::Duplicate),
                                Some(AnnouncementUpdate::Fork) => Ok(Action::Suppress),
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
                    }
                }
            }
        }
        // Envelope-defined but unhandled in v0: no rotation handler
        // exists, so rotation messages are terminal no-ops —
        // acknowledged and discarded, never deferred (deferral would
        // park poison for retry). When rotation handling lands this arm
        // becomes a commit or a deferral; until then no durable record
        // distinguishes consumed from never-recorded (see trust.md).
        Message::KeyRotation(_) => Ok(Action::Suppress),
        Message::Capability(payload) => Ok(capability_action(engine, id, payload, sender, budget)),
    }
}

fn capability_action(
    engine: &Engine,
    id: &ControlMessageId,
    payload: &CapabilityPayload,
    sender: DeviceId,
    budget: &mut IntakeBudget,
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
        Ok(authorized) => {
            // Shed before committing: authorization is spent work, but
            // the facts are not yet recorded and no view mutated, so
            // the envelope can still shed cleanly.
            if !budget.would_admit(sender, 2) {
                return Action::Shed;
            }
            Action::Commit(vec![
                Fact::Capability(authorized),
                Fact::ControlMessage(*id),
            ])
        }
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
    budget: &mut IntakeBudget,
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
            rotation_commit(engine, &id, sender, &delivery, budget)
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
    budget: &mut IntakeBudget,
) -> Result<Outcome, EngineError> {
    let suppress = |engine: &mut Engine, reason: &'static str| {
        // Suppressions ack without a fact, so the reason is the only
        // record of why a delivery died: without it a stuck peer's
        // Accepted verdicts are indistinguishable from commits.
        tracing::debug!(
            kind = "rotation-delivery",
            outcome = "suppressed",
            reason,
            "intake verdict"
        );
        engine.inbox.suppress(id);
        Ok(Outcome::Accepted)
    };
    // Not for us: the mailbox routes by recipient, so a mismatch is a
    // broken sender — terminal, never healed by redelivery.
    if delivery.device != engine.device {
        return suppress(engine, "delivery-device-mismatch");
    }
    let transition = match MembershipTransition::from_canonical_bytes(&delivery.transition) {
        Ok(transition) => transition,
        Err(_) => return suppress(engine, "transition-decode-failed"),
    };
    // Cheap structural gates before the ECDH+AEAD unwrap: the carried
    // transition must arrive within ingest limits and name the
    // delivery's epoch. Bytes that fail here can never authorize, so
    // they never earn the unwrap — same terminal verdict, less work.
    // (The transition↔capability binding check stays after the
    // unwrap: the binding lives inside the wrap.)
    if transition.epoch != delivery.epoch {
        return suppress(engine, "delivery-epoch-mismatch");
    }
    if check_total_len(&Limits::V0, "transition", delivery.transition.len()).is_err() {
        return suppress(engine, "transition-over-limits");
    }
    if check_transition(&Limits::V0, &transition).is_err() {
        return suppress(engine, "transition-struct-rejected");
    }
    let capability = match WrappedCapability::from_bytes(delivery.wrapped.clone())
        .unwrap(&engine.encryption_secret)
    {
        Ok(capability) => capability,
        Err(_) => return suppress(engine, "capability-unwrap-failed"),
    };
    // Redundant-field agreement, mirrored from the capability arm: the
    // delivery metadata and the capability it carries must name this
    // device and epoch. Anyone can seal to our public key, so the wrap
    // alone cannot prove address — the check happens here, before
    // anything commits, and a mismatch never heals by deferring.
    if capability.device != engine.device || delivery.epoch != capability.covered_epoch() {
        return suppress(engine, "field-disagreement");
    }
    // The carried transition must be the capability's own binding —
    // a transition for another binding paired with this wrap is
    // tampering or a broken sender, never a gap that fills.
    if transition.transition_id() != capability.transition {
        return suppress(engine, "binding-mismatch");
    }
    let transition_id = transition.transition_id();
    // Mint authority, checked before anything commits. The mailbox
    // seal proved the *sender* was a member of the authorizing state —
    // delivery authority. It says nothing about who chose the secret
    // vector: a member could seal a well-formed delivery carrying
    // attacker-chosen secrets, and the recipient would commit them and
    // poison its keyring against later honest traffic. The owner's
    // proof over a commitment to the unwrapped vector closes that, and
    // the signer must be an owner of this exact transition.
    let Some(proof) = crate::keys::owner_proof::OwnerProof::decode(&delivery.owner_proof) else {
        return suppress(engine, "delivery-owner-proof-undecodable");
    };
    if proof
        .verify(
            &engine.drive(),
            &engine.device,
            &transition_id,
            delivery.epoch,
            &capability.secrets,
        )
        .is_err()
    {
        return suppress(engine, "delivery-owner-proof-invalid");
    }
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
            Err(_) => return suppress(engine, "capability-unauthorized"),
        };
    // The signer must be an owner of the **pre-state** that authorized
    // this transition (epochs.md rule 3), not of the state it produces.
    // That distinction is what makes handover work: the outgoing owner
    // signs and mints, so a check against the post-state would suppress
    // every legitimate handover while admitting the incoming owner — who
    // could then choose the vector outright, recreating exactly the
    // poisoning this proof exists to stop.
    let mint_authority = match transition.prev {
        Some(prev) => scratch.owners_of(&prev),
        // Genesis establishes its own owner set; there is no earlier
        // state to consult.
        None => scratch.owners_of(&transition_id),
    };
    match mint_authority {
        Some(owners) if owners.contains(&proof.signer) => {}
        // Signed, but by a device without mint authority.
        Some(_) => return suppress(engine, "delivery-mint-authority-missing"),
        None => return Err(EngineError::TransitionUnclassified(transition_id)),
    }
    // Sender-member, against the authorizing state (not the tip): the
    // delivery is authorized only from a member of the epoch it grants.
    // A former member removed by this very history cannot speak its
    // secrets; the owner never leaves the member set short of the
    // terminal state, so genuine senders always pass.
    match scratch.members_of(&transition_id) {
        Some(members) if members.contains(&sender) => {}
        Some(_) => return suppress(engine, "sender-not-member"),
        // Observed a moment ago, but the fresh analysis derives no
        // state for it: the same internal disagreement the
        // announcement arm fails loudly on, not sender data.
        None => return Err(EngineError::TransitionUnclassified(transition_id)),
    }
    // The commit budget gates before the live log observes: an
    // observation without a commit would validate later envelopes
    // against uncommitted state for the rest of the pass. The charge
    // is exact — a rotation delivery always commits these three facts
    // — and the flush paces its own batches below. No
    // semantic-duplicate check here: the carried transition may
    // already be committed via the control framing while its
    // capability is still unrecorded, and dropping the delivery would
    // stall the device on a missing epoch secret — the budget paces
    // rotation redelivery instead.
    if !budget.admit(sender, 3) {
        engine.inbox.forget(id);
        return Ok(Outcome::RelayHeld);
    }
    engine.log.observe(transition.clone());
    let mut staged: BTreeMap<SnapshotId, SnapshotAnnouncement> = BTreeMap::new();
    let mut facts = vec![
        Fact::Transition(transition),
        Fact::Capability(authorized),
        Fact::ControlMessage(*id),
    ];
    match flush_pending(engine, &mut staged, Some(transition_id), sender, budget) {
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
