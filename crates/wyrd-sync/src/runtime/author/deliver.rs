use std::collections::BTreeMap;

use wyrd_format::{DeviceId, DriveId, MembershipTransition, TransitionId};

use crate::control::{
    is_superseded_rotation, open as open_control, seal as seal_control, seal_rotation, Message,
    SealedControl, SealedRotation, TransitionPayload, ROTATION_VERSION,
};
use crate::durable::{Fact, Rebuilt};
use crate::keys::capability::{Capability, DriveKeyring};
use crate::keys::owner_proof::OwnerProof;
use crate::runtime::engine::{Engine, EngineError};
use crate::transport::mailbox::{seal_for_recipient, Mailbox};
use crate::transport::signer::{SignerError, SignerSession};
use zeroize::Zeroizing;

/// Send every undischarged transition- and capability-delivery
/// obligation, returning the number of relay-accepted sends this
/// call. Transitions go before capabilities (the ordering optimization:
/// intake holds membership-unseen capabilities pending, so either
/// order converges, but tip-first minimizes deferrals). Durable and
/// retryable like the announcement outbox: sealed bytes persist on
/// first send so retries are byte-identical, one delivered marker
/// commits per relay-accepted send, and a mid-loop failure leaves the rest
/// pending for the next call. Entries that cannot resolve now —
/// orphaned transitions, epochs without a canonical transition or
/// held secret, recipients no longer members — are skipped and stay
/// pending; transport failures return immediately.
/// Scope for a statement-triggered send: one recipient, at most
/// `remaining` further send attempts, and the recipient's newest
/// held epoch from the triggering statement. The epoch bound is the
/// sender-side UnknownEpoch skip: a transition sealed under an epoch
/// the recipient does not hold cannot be opened there, so sending it
/// is waste — it stays pending (never retired) until the recipient's
/// capability install for that epoch arrives in a later statement.
/// Capabilities are never epoch-skipped (rotation framing is
/// self-contained: the wrap carries its own secrets), so the keys
/// always land first and the transition skip always converges. The
/// blind retry path passes no scope and keeps its existing behavior.
struct Scope<'a> {
    recipient: &'a DeviceId,
    remaining: usize,
    newest_held: u64,
}

pub(crate) fn deliver_pending(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
) -> Result<usize, EngineError> {
    deliver_inner(engine, mailbox, &mut None)
}

/// Send pending obligations for one recipient only, stopping after
/// `limit` send attempts and skipping transitions sealed under
/// epochs past `newest_held` (the requester's newest evidenced
/// install). The 21c answer's stage 4: the capped retransmit of one
/// reconciliation statement's missing set. Shares the loop bodies
/// below with the blind retry path — one seal/send implementation,
/// two callers — so a scoped send and a pass send never disagree on
/// bytes, markers, or skip conditions.
pub(crate) fn deliver_scoped(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    recipient: &DeviceId,
    limit: usize,
    newest_held: u64,
) -> Result<usize, EngineError> {
    let mut scope = Some(Scope {
        recipient,
        remaining: limit,
        newest_held,
    });
    deliver_inner(engine, mailbox, &mut scope)
}

fn deliver_inner(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    scope: &mut Option<Scope<'_>>,
) -> Result<usize, EngineError> {
    // One validated delivery snapshot per pass: every read below comes
    // from this rebuild. Mid-pass commits only append Sealed,
    // SealedReplaced, and Delivered facts — never new Queued pairs — so
    // the frozen pending lists stay exact. The transition loop keeps a
    // pass-local overlay absorbing newly sealed bytes (one envelope
    // fans out over many recipients); the capability loop keeps none
    // (pairs are unique per pass, and stale arms supersede durably —
    // memory does not survive the outage the recovery exists for).
    // No re-read per pair: a newcomer catch-up or a large fan-out
    // costs one log decode, not one per obligation.
    //
    // A scoped call rebuilds too: the retire commits for its
    // statement landed just before, so the snapshot sees them and
    // covered obligations are already non-pending — the scoped send
    // can only attempt the missing set.
    let rebuilt = engine.store.rebuild(engine.device)?;
    let mut sent = 0usize;
    sent += deliver_transitions(engine, mailbox, &rebuilt, &mut *scope)?;
    sent += deliver_capabilities(engine, mailbox, &rebuilt, &mut *scope)?;
    Ok(sent)
}

/// An epoch's control key, held or derived: the in-memory map first,
/// else derived from the delivery snapshot's keyring and installed. A
/// device that never held the epoch has no key and no secret, which
/// surfaces as [`EngineError::MissingEpochKey`].
pub(super) fn control_key_for(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    epoch: u64,
) -> Result<[u8; 32], EngineError> {
    if let Some(key) = engine.epoch_keys.get(&epoch) {
        return Ok(**key);
    }
    let secret = keyring
        .secret(epoch)
        .cloned()
        .ok_or(EngineError::MissingEpochKey(epoch))?;
    let key = secret.control_key(&engine.drive, epoch);
    engine.add_epoch_key(epoch, Zeroizing::new(key));
    Ok(key)
}

/// Open sealed bytes reused from a durable outbox fact, for verification
/// against the obligation about to be discharged. The envelope must
/// decode under a held epoch key and name this drive; the caller checks
/// the opened message against its obligation key. A missing sealing key
/// is not corruption — the obligation stays pending for a later pass —
/// so it reports `Ok(None)`; anything else wrong fails closed, because
/// sending undecodable bytes would discharge the obligation while
/// delivering nothing.
pub(super) fn open_reused_sealed(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    sealed_bytes: &[u8],
    obligation: &str,
) -> Result<Option<(u64, Message)>, EngineError> {
    let sealed = SealedControl::decode(sealed_bytes).map_err(|_| {
        EngineError::SealedOutboxMismatch(format!("{obligation}: sealed bytes do not decode"))
    })?;
    let key = match control_key_for(engine, keyring, sealed.epoch) {
        Ok(key) => key,
        Err(EngineError::MissingEpochKey(_)) => return Ok(None),
        Err(other) => return Err(other),
    };
    let (drive, epoch, message) = open_control(&key, &sealed).map_err(|error| {
        EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed bytes do not open: {error}"
        ))
    })?;
    if drive != engine.drive {
        return Err(EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed drive {drive} is not this drive"
        )));
    }
    Ok(Some((epoch, message)))
}

/// Verify reused sealed bytes against the obligation about to be
/// discharged: open under a held key, then run the caller's
/// kind-specific correlation check (message variant, obligation
/// identity, envelope epoch). A missing sealing key is not corruption
/// — returns `Ok(None)` and the obligation stays pending for a later
/// pass. Anything else wrong fails closed. Returns the bytes on
/// success, so the send below moves verified bytes only.
pub(super) fn verify_reused_sealed(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    sealed_bytes: Vec<u8>,
    obligation: &str,
    correlate: impl FnOnce(u64, Message) -> Result<(), EngineError>,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some((sealed_epoch, message)) =
        open_reused_sealed(engine, keyring, &sealed_bytes, obligation)?
    else {
        return Ok(None);
    };
    correlate(sealed_epoch, message)?;
    Ok(Some(sealed_bytes))
}

/// Seal a fresh message under the obligation's epoch key and commit
/// the sealed fact, so retries resend byte-identical bytes. A missing
/// key is not corruption — returns `Ok(None)` and the obligation
/// stays pending. The size check runs before the commit: persisting
/// oversize bytes would poison the obligation past retry.
pub(super) fn seal_fresh_for(
    engine: &mut Engine,
    keyring: &DriveKeyring,
    epoch: u64,
    message: &Message,
    seal_fact: impl FnOnce(Vec<u8>) -> Fact,
) -> Result<Option<Vec<u8>>, EngineError> {
    let key = match control_key_for(engine, keyring, epoch) {
        Ok(key) => key,
        Err(EngineError::MissingEpochKey(_)) => return Ok(None),
        Err(other) => return Err(other),
    };
    let sealed = seal_control(&key, &engine.drive, epoch, message)?;
    let bytes = sealed.encode();
    crate::transport::mailbox::check_outbound_size(&bytes)?;
    engine.commit_facts(&[seal_fact(bytes.clone())])?;
    Ok(Some(bytes))
}

/// Send verified sealed bytes to each recipient under the mailbox's
/// outer recipient seal, committing one delivered marker per
/// relay-accepted send. A send no relay accepts commits nothing —
/// the Delivered fact means relay-accepted, so zero acceptance
/// leaves the obligation pending for a later pass instead of
/// recording a fact no acceptance supports. A send failure returns
/// immediately with the rest still pending.
///
/// The first refusal of an obligation warns once: a policy refusal
/// that can never flip would otherwise retry silently forever under
/// the default filter. Repeats stay at debug, and the warn names the
/// kind only — never the recipient or the obligation's identities
/// (trust.md OD-17-6). Discharge clears the marker, so a re-queued
/// obligation warns again.
pub(super) fn send_sealed_to(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    kind: &'static str,
    obligation: &str,
    sealed_bytes: &[u8],
    recipients: impl IntoIterator<Item = DeviceId>,
    delivered: impl Fn(DeviceId) -> Fact,
) -> Result<usize, EngineError> {
    let mut sent = 0usize;
    for recipient in recipients {
        let envelope = seal_for_recipient(&engine.identity_secret, recipient, sealed_bytes)?;
        let report = mailbox.send(envelope)?;
        // The per-pair key: the same envelope fans out over many
        // recipients and each pair discharges independently, so the
        // warn-once marker tracks pairs, not envelopes.
        let warned_key = (kind, obligation.to_owned(), recipient);
        if report.accepted == 0 {
            // The bytes reached no relay: retiring the obligation
            // here would lose the sender's recovery path while the
            // recipient never saw the event. Stay pending; the next
            // pass retries the identical bytes.
            if engine.refusal_warned.insert(warned_key) {
                tracing::warn!(
                    kind,
                    "outbox send refused by every relay; obligation stays pending"
                );
            } else {
                tracing::debug!(kind, recipient = ?recipient, "outbox send refused; obligation stays pending");
            }
            continue;
        }
        engine.refusal_warned.remove(&warned_key);
        // Per-send forensics, mirroring the intake verdict lines: with
        // relay ids on one side and control kinds on the other, a
        // stuck peer's whole outbox can be reconstructed envelope by
        // envelope.
        tracing::debug!(kind, recipient = ?recipient, "outbox send");
        engine.commit_facts(&[delivered(recipient)])?;
        sent += 1;
    }
    Ok(sent)
}

/// Send all pending transition obligations. One sealed envelope per
/// transition (recipient binding is the outer mailbox seal, so the
/// bytes are shared), one delivered marker per relay-accepted
/// recipient send.
fn deliver_transitions(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    rebuilt: &Rebuilt,
    scope: &mut Option<Scope<'_>>,
) -> Result<usize, EngineError> {
    let mut pending = rebuilt.runtime.pending_transitions();
    pending.sort();
    if let Some(scope) = scope.as_ref() {
        // Statement-triggered send: only the requester's pairs. The
        // retire commits for the statement already landed, so these
        // are exactly its missing set.
        pending.retain(|(_, r)| r == scope.recipient);
    }
    let mut sealed_overlay: BTreeMap<TransitionId, Vec<u8>> = BTreeMap::new();
    let mut sent = 0usize;
    let mut index = 0usize;
    while index < pending.len() {
        if scope.as_ref().is_some_and(|s| s.remaining == 0) {
            // Budget exhausted: the rest stays pending for the
            // normal pass and the recipient's next statement.
            // Checked before any seal work, so an unsent obligation
            // costs no commit.
            break;
        }
        let id = pending[index].0;
        if let Some(held) = scope.as_ref().map(|s| s.newest_held) {
            // Sender-side UnknownEpoch skip: the transition's own
            // epoch is past everything the statement shows the
            // recipient holding, so the recipient could not open
            // this envelope. It stays pending — never retired — for
            // the statement that carries the capability install.
            // An obligation whose transition the log never resolved
            // takes the orphan path below instead: unknown epoch is
            // not evidence of unholdability.
            let epoch = engine.log.transition(&id).map(|t| t.epoch);
            if epoch.is_some_and(|epoch| epoch > held) {
                while index < pending.len() && pending[index].0 == id {
                    index += 1;
                }
                continue;
            }
        }
        // Clone out of the log borrow before the mutable seal step.
        let Some((epoch, canonical)) = engine
            .log
            .transition(&id)
            .map(|t| (t.epoch, t.canonical_bytes()))
        else {
            // Orphaned obligation: the transition never resolved. It
            // stays pending; skip the whole recipient run for it.
            while index < pending.len() && pending[index].0 == id {
                index += 1;
            }
            continue;
        };
        // The obligation descriptor names the send below as well as
        // the reuse verification: one string per transition, so the
        // warn-once marker keys the pair the send actually attempts.
        let obligation = format!("transition {id:?}");
        let sealed_bytes = if let Some(bytes) = sealed_overlay.get(&id).cloned().or_else(|| {
            rebuilt
                .runtime
                .transition_sealed_bytes(id)
                .map(<[u8]>::to_vec)
        }) {
            // Reused sealed bytes are verified against the obligation
            // before use: the fact's key must name the transition the
            // bytes actually carry, or the send would discharge one
            // obligation while delivering another.
            let Some(bytes) = verify_reused_sealed(
                engine,
                &rebuilt.keyring,
                bytes,
                &obligation,
                |sealed_epoch, message| {
                    let Message::MembershipTransition(payload) = message else {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not a transition",
                            message.kind()
                        )));
                    };
                    // The envelope epoch must be the transition's own
                    // epoch: the bytes are shared per transition, so a
                    // correct payload under a foreign epoch key would
                    // send to recipients that cannot open it and
                    // discharge the obligation anyway.
                    if sealed_epoch != epoch {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed under epoch {sealed_epoch}, not the transition's epoch {epoch}"
                        )));
                    }
                    let transition = MembershipTransition::from_canonical_bytes(
                        &payload.transition,
                    )
                    .map_err(|error| {
                        EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed transition does not decode: {error}"
                        ))
                    })?;
                    if transition.transition_id() != id {
                        return Err(EngineError::SealedOutboxMismatch(format!(
                            "{obligation}: sealed bytes carry {:?}, not the obligated transition",
                            transition.transition_id()
                        )));
                    }
                    Ok(())
                },
            )?
            else {
                // No sealing key: retain the obligation for a later
                // pass, like an orphaned one.
                while index < pending.len() && pending[index].0 == id {
                    index += 1;
                }
                continue;
            };
            bytes
        } else {
            let message = Message::MembershipTransition(TransitionPayload {
                transition: canonical,
            });
            let Some(bytes) =
                seal_fresh_for(engine, &rebuilt.keyring, epoch, &message, |sealed| {
                    Fact::TransitionSealed(id, sealed)
                })?
            else {
                // No sealing key: the obligation stays pending and
                // observable via the pending projection instead of
                // failing the whole pass on every drain.
                while index < pending.len() && pending[index].0 == id {
                    index += 1;
                }
                continue;
            };
            sealed_overlay.insert(id, bytes.clone());
            bytes
        };
        // Every pair for this transition in the frozen pending list:
        // no re-read, since only this loop writes and it appends
        // Delivered facts, never new Queued ones.
        let mut recipients = Vec::new();
        while index < pending.len() && pending[index].0 == id {
            recipients.push(pending[index].1);
            index += 1;
        }
        let attempts = recipients.len();
        sent += send_sealed_to(
            engine,
            mailbox,
            "transition",
            &obligation,
            &sealed_bytes,
            recipients,
            |recipient| Fact::TransitionDelivered(id, recipient),
        )?;
        if let Some(scope) = scope.as_mut() {
            // One attempt per recipient: in a scoped send there is at
            // most one, so the budget counts obligations attempted.
            scope.remaining = scope.remaining.saturating_sub(attempts);
        }
    }
    Ok(sent)
}

/// Send all pending capability obligations, rotation-framed. Each
/// pair seals its own recipient-specific delivery (the ECDH wrap binds
/// one recipient, so unlike transitions the sealed bytes are per-pair),
/// minted at send time from the keyring against the epoch's canonical
/// transition — the registered key comes from chain state, never from
/// the caller — so the bytes always reflect current membership.
///
/// The framing is rotation delivery, never the epoch-sealed envelope:
/// the recipient may hold no later epoch key — that is the ordinary
/// case this path serves — and an epoch seal would ask it for the very
/// key it is being given. The epoch seal needs no sender key either
/// (ECDH to the registered key), so a missing sender epoch key never
/// stalls capability delivery; only missing keyring secrets do.
fn deliver_capabilities(
    engine: &mut Engine,
    mailbox: &mut impl Mailbox,
    rebuilt: &Rebuilt,
    scope: &mut Option<Scope<'_>>,
) -> Result<usize, EngineError> {
    let mut pending = rebuilt.runtime.pending_capabilities();
    pending.sort();
    if let Some(scope) = scope.as_ref() {
        pending.retain(|(_, r)| r == scope.recipient);
    }
    if pending.is_empty() {
        // Nothing to mint: skip the chain walk and the session
        // clone below, so an idle pass copies no key material.
        return Ok(0);
    }
    if scope.as_ref().is_some_and(|s| s.remaining == 0) {
        // Budget already spent (by the transition loop ahead of this
        // one): skip the chain walk and the signer clone like the
        // empty case above — an exhausted scoped send costs no work.
        return Ok(0);
    }
    // The canonical chain's epoch-to-transition map, walked once:
    // capability wraps bind to the epoch's canonical transition.
    let mut chain: BTreeMap<u64, TransitionId> = BTreeMap::new();
    let mut cursor = engine.log.known_state().map(|state| state.transition_id);
    while let Some(id) = cursor {
        let Some(t) = engine.log.transition(&id) else {
            break;
        };
        chain.insert(t.epoch, id);
        cursor = t.prev;
    }
    let mut sent = 0usize;
    // The mint session, cloned once per pass: the local identity signs
    // for itself (a remote session would plug in here when NIP-46 mode
    // lands). Cloned rather than borrowed so the obligation loop can
    // keep its `&mut Engine` while minting through the session.
    let signer = engine.identity_secret.clone();
    for (epoch, recipient) in pending {
        if scope.as_ref().is_some_and(|s| s.remaining == 0) {
            // Budget exhausted: same rule as the transition loop —
            // checked before any mint work, skips consume nothing.
            break;
        }
        let Some(transition_id) = chain.get(&epoch).copied() else {
            continue;
        };
        // One descriptor per obligation: this loop visits each pair
        // once, so it names the reuse verification below and the
        // send's warn-once marker alike.
        let obligation = format!("capability epoch {epoch} for {recipient}");
        // No pass-local overlay here, unlike transitions: pending pairs
        // are unique per pass (a set, visited once), so a first seal
        // can never be re-read in the same pass — the committed fact
        // is the reuse source on the next one. A stale arm supersedes
        // durably for the same reason: memory does not survive the
        // outage the recovery exists for.
        let reused = rebuilt
            .runtime
            .capability_sealed_bytes(epoch, recipient)
            .map(<[u8]>::to_vec);
        let sealed_bytes = match reused {
            // Rotation reuse: the fact's key must still name what the
            // bytes carry (drive, epoch, recipient, current
            // registration), or the send would discharge one obligation
            // while delivering another. Re-opening is impossible — the
            // ephemeral secret is gone by design — and unnecessary: the
            // correlation below is the whole check, exactly as the
            // envelope-epoch correlation is for epoch-sealed reuse.
            Some(bytes) if bytes.first() == Some(&ROTATION_VERSION) => {
                match verify_reused_rotation(
                    engine,
                    &bytes,
                    &obligation,
                    epoch,
                    recipient,
                    &transition_id,
                )? {
                    Reused::Use => bytes,
                    // Stale registration: the recipient holds a new
                    // secret the old bytes can never open under. The
                    // seal is structurally valid, so what retires it
                    // is the new registration — named exactly by the
                    // durable successor, like every other supersession.
                    Reused::Supersede => {
                        let Some(bytes) = supersede_stale_rotation(
                            engine,
                            &signer,
                            &rebuilt.keyring,
                            epoch,
                            recipient,
                            &transition_id,
                            &bytes,
                        )?
                        else {
                            continue;
                        };
                        bytes
                    }
                }
            }
            // A stale fact under an older framing — a rotation sealed
            // under a superseded version, or a pre-framing epoch-sealed
            // capability — never sends: its bytes can never open for
            // the current reader (no proof blob, or keys the recipient
            // may never hold). Supersede it durably under the current
            // framing, which always opens. The stale fact lingers
            // durably and harmlessly; the replacement is the obligation
            // from the commit on. This is the announced re-mint
            // recovery for the `0x01 -> 0x02` bump, and it is what
            // keeps an upgrade from stranding a pending obligation.
            // Bytes decoding as neither framing still fail closed:
            // genuinely undecodable outbox bytes never silently heal.
            Some(bytes) if is_superseded_rotation(&bytes) => {
                let Some(replacement) = supersede_stale_rotation(
                    engine,
                    &signer,
                    &rebuilt.keyring,
                    epoch,
                    recipient,
                    &transition_id,
                    &bytes,
                )?
                else {
                    continue;
                };
                replacement
            }
            Some(bytes) => {
                if SealedControl::decode(&bytes).is_err() {
                    return Err(EngineError::SealedOutboxMismatch(format!(
                        "{obligation}: sealed bytes do not decode"
                    )));
                }
                // Same older-framing rule as above: the envelope is
                // valid but predates rotation delivery, so supersede
                // rather than send.
                let Some(bytes) = supersede_stale_rotation(
                    engine,
                    &signer,
                    &rebuilt.keyring,
                    epoch,
                    recipient,
                    &transition_id,
                    &bytes,
                )?
                else {
                    continue;
                };
                bytes
            }
            None => {
                let Some(bytes) = mint_fresh_rotation(
                    engine,
                    &signer,
                    &rebuilt.keyring,
                    epoch,
                    recipient,
                    &transition_id,
                )?
                else {
                    // No mintable wrap (missing secrets, or the
                    // recipient left the epoch's state): the obligation
                    // stays pending and observable via the pending
                    // projection instead of failing the whole pass on
                    // every drain.
                    continue;
                };
                bytes
            }
        };
        sent += send_sealed_to(
            engine,
            mailbox,
            "capability",
            &obligation,
            &sealed_bytes,
            [recipient],
            |delivered| Fact::CapabilityDelivered(epoch, delivered),
        )?;
        if let Some(scope) = scope.as_mut() {
            scope.remaining = scope.remaining.saturating_sub(1);
        }
    }
    Ok(sent)
}

/// What reused rotation bytes offer: resend them verbatim, or retire
/// them for a durable successor when they went stale.
enum Reused {
    /// The bytes still name the obligation: resend them verbatim.
    Use,
    /// The registration moved on: supersede durably.
    Supersede,
}

/// Verify reused rotation bytes against the obligation about to be
/// discharged: the header must still name this drive, epoch,
/// recipient, and the recipient's current registration. Anything
/// undecodable or misaddressed fails closed (a fact-key/bytes mismatch
/// would discharge one obligation while delivering another); a stale
/// registration supersedes durably instead, since the recipient holds
/// a new secret the old bytes can never open under. Borrows the bytes:
/// the stale arm needs them back to name the fact it retires.
fn verify_reused_rotation(
    engine: &Engine,
    bytes: &[u8],
    obligation: &str,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Reused, EngineError> {
    let sealed = SealedRotation::decode(bytes).map_err(|_| {
        EngineError::SealedOutboxMismatch(format!("{obligation}: sealed bytes do not decode"))
    })?;
    if sealed.version != ROTATION_VERSION
        || sealed.drive != engine.drive
        || sealed.epoch != epoch
        || sealed.recipient != recipient
    {
        return Err(EngineError::SealedOutboxMismatch(format!(
            "{obligation}: sealed bytes do not name the obligated delivery"
        )));
    }
    let current = engine
        .log
        .state_of(transition_id)
        .and_then(|state| state.encryption_key_of(&recipient).copied());
    if current.is_some_and(|key| key == sealed.encryption_key) {
        Ok(Reused::Use)
    } else {
        Ok(Reused::Supersede)
    }
}

/// Mint a fresh rotation delivery for the obligation and commit the
/// sealed fact, so retries resend byte-identical bytes. Returns `None`
/// — obligation stays pending — when the epoch has no state, the
/// recipient is not a member with a registered key, or the keyring
/// lacks any secret through the epoch. The size check runs before the
/// commit: persisting oversize bytes would poison the obligation past
/// retry.
fn mint_fresh_rotation(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(bytes) =
        mint_fresh_rotation_bytes(engine, session, keyring, epoch, recipient, transition_id)?
    else {
        return Ok(None);
    };
    engine.commit_facts(&[Fact::CapabilitySealed(epoch, recipient, bytes.clone())])?;
    Ok(Some(bytes))
}

/// Supersede a stale sealed fact durably, exactly once, and return
/// the replacement bytes. First-seal-wins cannot express "these
/// bytes are no longer the obligation", so the change is its own
/// fact: a pass-local overlay would be discarded on restart, leaving
/// the stale fact to be re-minted into *new* bytes every pass — one
/// appended-and-fsynced, then-ignored record per obligation per pass
/// during a relay outage, and retries that are no longer
/// byte-identical. With the fact committed, replay makes the
/// replacement the current obligation and every later pass reuses
/// these exact bytes.
///
/// Returns `None` — obligation stays pending, stale fact untouched —
/// when the mint cannot complete, so a later pass retries the same
/// replacement rather than stacking failures.
fn supersede_stale_rotation(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>, EngineError> {
    let supersedes = crate::durable::SealedCapabilityFactId::of(epoch, &recipient, bytes);
    let Some(replacement) =
        mint_fresh_rotation_bytes(engine, session, keyring, epoch, recipient, transition_id)?
    else {
        return Ok(None);
    };
    engine.commit_facts(&[Fact::CapabilitySealedReplaced {
        epoch,
        recipient,
        supersedes,
        replacement: replacement.clone(),
    }])?;
    Ok(Some(replacement))
}

/// Mint current-framing rotation bytes for one obligation without
/// committing anything: the caller decides whether this becomes the
/// durable obligation (a replacement fact) or a first seal.
fn mint_fresh_rotation_bytes(
    engine: &mut Engine,
    session: &dyn SignerSession,
    keyring: &DriveKeyring,
    epoch: u64,
    recipient: DeviceId,
    transition_id: &TransitionId,
) -> Result<Option<Vec<u8>>, EngineError> {
    let Some(state) = engine.log.state_of(transition_id) else {
        return Ok(None);
    };
    let Some(transition) = engine.log.transition(transition_id) else {
        return Ok(None);
    };
    let Some(registration) = state.encryption_key_of(&recipient).copied() else {
        return Ok(None);
    };
    // Mint authority, checked before anything is sealed or committed
    // (epochs.md rule 3). The recipient enforces this at intake: a proof
    // signed outside the transition's pre-state owner set is suppressed.
    // A sender without it would append a replacement, mark it
    // transmitted, and deliver bytes the recipient discards — a durable
    // fact claiming an obligation discharged that no recipient ever
    // honours. Leave the obligation pending for an authorized signer
    // instead; the relay reaches the owner.
    let mint_authority = match transition.prev {
        Some(prev) => engine.log.owners_of(&prev),
        // Genesis establishes its own owner set; there is no earlier
        // state to consult.
        None => engine.log.owners_of(transition_id),
    };
    match mint_authority {
        Some(owners) if owners.contains(&engine.device) => {}
        // Signed, but by a device without mint authority.
        Some(_) => return Ok(None),
        None => return Err(EngineError::TransitionUnclassified(*transition_id)),
    }
    let Some(secrets) = epoch_secrets(keyring, transition) else {
        return Ok(None);
    };
    let Some(wrap) = mint_wrap(engine.drive, &state, transition, recipient, secrets.clone()) else {
        return Ok(None);
    };
    // Mint authority, distinct from delivery authority: the owner signs
    // a commitment to this exact vector, so any member may later relay
    // the sealed bytes while only an owner can have originated them.
    // Raise vs count, stated (error-conventions.md): a session
    // that is momentarily unreachable — or one whose key rotated
    // under it — leaves the obligation pending for the next pass,
    // exactly like a missing secret or registration, with a debug
    // line so a never-converging stall stays greppable. A domain
    // refusal, a malformed session response, or a session signing as
    // another device is static misconfiguration, so it fails loudly
    // rather than stalling the outbox silently. Loudness aborts the
    // whole pass, not just this obligation: the error propagates
    // through `deliver_pending`, and the live loop counts it toward
    // its consecutive-error budget.
    let proof = match OwnerProof::sign(
        session,
        &engine.drive,
        &recipient,
        &transition.transition_id(),
        epoch,
        &secrets,
    ) {
        Ok(proof) => proof,
        Err(e @ (SignerError::Unreachable | SignerError::IdentityMismatch)) => {
            // A stall with no error is invisible unless it is logged:
            // the variant names the diagnosis, so a permanently
            // mis-wired session reads differently from a dropped one.
            // `debug!`, not the e2e rotation log: the e2e harnesses
            // set no `wyrd_sync` scope (Lima defaults to
            // `wyrd_core=debug`, microVM to the binary's `info`) —
            // this line is for daemon logs with crate debug enabled
            // (`--verbose`). Widening the Lima filter to carry it was
            // considered and declined: harness config is out of scope
            // for this change.
            tracing::debug!(epoch, recipient = ?recipient, error = ?e, "owner-proof mint skipped; obligation stays pending");
            return Ok(None);
        }
        Err(
            e @ (SignerError::Refused
            | SignerError::MalformedResponse
            // Unreachable from `sign`, which never reports the engine
            // join: listed so the terminal class stays exhaustive if
            // a future session path does.
            | SignerError::SessionIdentityMismatch { .. }),
        ) => {
            return Err(e.into());
        }
    };
    // The join the mint-authority gate assumes: the gate vetted
    // `engine.device` as an owner, so the proof must name the same
    // identity. A session consistently signing as another device —
    // reachable, domain-authorized, but mapped to the wrong engine —
    // would otherwise mint deliveries the recipient suppresses while
    // the sender commits them as discharged. The engine's identity
    // never changes under it, so this never heals: loud, with both
    // identities in the error.
    if proof.signer != engine.device {
        return Err(EngineError::Signer(SignerError::SessionIdentityMismatch {
            reported: proof.signer,
            device: engine.device,
        }));
    }
    let sealed = seal_rotation(
        &engine.drive,
        recipient,
        &registration,
        epoch,
        &transition.canonical_bytes(),
        &wrap,
        &proof.encode(),
    )?;
    let bytes = sealed.encode();
    crate::transport::mailbox::check_outbound_size(&bytes)?;
    Ok(Some(bytes))
}
/// The epoch-secret vector a transition's grant carries: one secret per
/// epoch `1..=N`, straight from the keyring.
fn epoch_secrets(
    keyring: &DriveKeyring,
    transition: &MembershipTransition,
) -> Option<Vec<crate::keys::EpochSecret>> {
    let mut secrets = Vec::with_capacity(transition.epoch as usize);
    for past in 1..=transition.epoch {
        secrets.push(keyring.secret(past)?.clone());
    }
    Some(secrets)
}

fn mint_wrap(
    drive: DriveId,
    state: &crate::membership::MembershipState,
    transition: &MembershipTransition,
    recipient: DeviceId,
    secrets: Vec<crate::keys::EpochSecret>,
) -> Option<Vec<u8>> {
    let cap = Capability::mint(drive, recipient, state, transition, secrets).ok()?;
    Some(cap.wrap().ok()?.as_bytes().to_vec())
}

// Sibling test file under the workspace tests_* naming: #[path] is required
// because default resolution from this parent would look for tests.rs, not this name.
#[cfg(test)]
#[path = "deliver/tests_deliver.rs"]
mod tests;
