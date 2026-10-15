//! The `member` command: invites, resumes, listings, and the log.
//! Owns the member runner, the invite/resume renderers, the carry
//! and invitation-file helpers, and the member reports; the
//! dispatcher in `main.rs` calls in.

use crate::args::MemberAction;
use crate::commands::device::{parse_device_id, parse_encryption_key, parse_transition_id};
use crate::CliError;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use wyrd_format::FsObjectStore;
use wyrd_format::{DeviceId, MembershipTransition, TransitionId};
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::membership::TransitionStatus;
use wyrd_sync::runtime::{Engine, EngineError};
/// Administer drive membership offline over the keystore: reads
/// project the membership log, writes author one transition plus
/// catch-up obligations through the engine (which enforces
/// owner-only). Catch-up delivery to other devices happens on the
/// next mounted sync via the mailbox, not here.
///
/// Invite outcome renderers, built as strings so tests assert the
/// rendering without capturing stdout (same pattern as
/// `sync_status_render`). The three outcomes must stay
/// distinguishable: a fresh admission, a resumed interruption, and
/// an already-complete rerun report different actions.
pub(crate) fn render_invited(
    device: &wyrd_format::DeviceId,
    reader: bool,
    epoch: u64,
    out: &std::path::Path,
    obligations: usize,
    batches: usize,
    carried: usize,
) -> String {
    format!(
        "invited {device}{} at epoch {epoch} -> {} ({obligations} obligations in {batches} batches, {carried} carried)",
        if reader { " as reader" } else { "" },
        out.display(),
    )
}

pub(crate) fn render_resumed(
    committed: usize,
    batches: usize,
    out: &std::path::Path,
    carried: usize,
) -> String {
    if committed == 0 {
        format!(
            "catch-up already complete; 0 obligations, invitation re-issued -> {} ({carried} carried)",
            out.display(),
        )
    } else {
        format!(
            "already a member; resumed {committed} obligations in {batches} batches, invitation re-issued -> {} ({carried} carried)",
            out.display(),
        )
    }
}

pub(crate) fn member(
    drive_dir: PathBuf,
    action: MemberAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    match action {
        MemberAction::List => {
            print!("{}", member_list_report(&engine)?);
            Ok(())
        }
        MemberAction::Log => {
            print!("{}", member_log_report(&engine)?);
            Ok(())
        }
        MemberAction::Status => {
            print!("{}", member_status_report(&engine)?);
            Ok(())
        }
        MemberAction::Remove { device, yes } => {
            let device = parse_device_id(&device)?;
            require_last_owner_confirmation(&engine, &device, yes)?;
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.remove_device(device)
            })?;
            println!(
                "removed {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Rotate => {
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.rotate_epoch())?;
            println!(
                "rotated to epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::SetOwner { device } => {
            let device = parse_device_id(&device)?;
            let (transition, carried) =
                transition_with_carry(&mut engine, &drive_dir, |engine| engine.set_owners(device))?;
            println!(
                "owner is now {device} at epoch {} ({} carried)",
                transition.epoch, carried
            );
            Ok(())
        }
        MemberAction::Resolve { winner, voided } => {
            let winner = parse_transition_id(&winner)?;
            let mut void_ids = Vec::with_capacity(voided.len());
            for id in &voided {
                void_ids.push(parse_transition_id(id)?);
            }
            let (transition, carried) = transition_with_carry(&mut engine, &drive_dir, |engine| {
                engine.resolve_conflict(winner, void_ids.clone())
            })?;
            println!(
                "resolved at epoch {} (prev {}, {} voided, {} carried)",
                transition.epoch,
                transition
                    .prev
                    .map(|id| id.to_string())
                    .as_deref()
                    .unwrap_or("genesis"),
                transition.resolves().len(),
                carried
            );
            Ok(())
        }
        MemberAction::Invite {
            device,
            encryption_key,
            out,
            reader,
        } => {
            let device = parse_device_id(&device)?;
            let encryption_key = parse_encryption_key(&encryption_key)?;
            // Claim the destination before the irreversible commit; on
            // admit failure the claim is removed so a retry starts
            // clean. See claim_out for the policy.
            let mut file = claim_out(&out)?;
            let admit = |engine: &mut Engine| {
                if reader {
                    engine.admit_reader(device, encryption_key)
                } else {
                    engine.admit_device(device, encryption_key)
                }
            };
            engine.stage_carry_heads()?;
            match admit(&mut engine) {
                Ok(outcome) => {
                    let carried = carry_pending(&mut engine, &drive_dir)?;
                    write_invitation(&out, &mut file, &outcome.invitation.encode())?;
                    println!(
                        "{}",
                        render_invited(
                            &device,
                            reader,
                            outcome.transition.epoch,
                            &out,
                            outcome.obligations_queued,
                            outcome.batches,
                            carried
                        )
                    );
                    return Ok(());
                }
                Err(EngineError::AlreadyMember | EngineError::AlreadyReader) => {}
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            }
            // Already admitted under some role: rerunning resumes the
            // interrupted fill instead of failing. The engine guard
            // verifies the supplied key and role against the recorded
            // admission first — a mismatch refuses with the actual
            // role named rather than recovering the wrong identity —
            // then resumes the catch-up and reissues the invitation
            // (the original may never have reached a file).
            let resume = match engine.resume_admission(device, &encryption_key, reader) {
                Ok(resume) => resume,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            let carried = carry_pending(&mut engine, &drive_dir)?;
            write_invitation(&out, &mut file, &resume.invitation.encode())?;
            println!(
                "{}",
                render_resumed(resume.committed, resume.batches, &out, carried)
            );
            Ok(())
        }
        MemberAction::ReissueInvitation { device, out } => {
            let device = parse_device_id(&device)?;
            // Same destination policy as invite: the reseal is new
            // bytes for an old admission, and an existing file is
            // refused rather than silently replaced.
            let mut file = claim_out(&out)?;
            let invitation = match engine.reissue_invitation(device) {
                Ok(invitation) => invitation,
                Err(error) => {
                    let _ = fs::remove_file(&out);
                    return Err(error.into());
                }
            };
            write_invitation(&out, &mut file, &invitation.encode())?;
            println!("reissued invitation for {device} -> {}", out.display());
            Ok(())
        }
    }
}

/// Author a membership transition plus its namespace carry in one
/// offline step: stage the served heads as durable obligations,
/// commit the transition via `author`, then drain the carry queue
/// at the new epoch (transition continuity: a quiet drive keeps
/// serving its files, and the next write extends the carry instead
/// of bootstrapping from empty). Staging precedes the
/// transition commit, so a crash between the commit and the drain
/// leaves a discoverable obligation: the next drain — after a
/// restart, or after the next transition — completes it. The object
/// store opens only when something is pending, so a fresh drive's
/// transition never touches it. A failed drain reports loudly with
/// the transition already durable at its epoch and the obligation
/// still pending.
fn transition_with_carry(
    engine: &mut Engine,
    drive_dir: &Path,
    author: impl FnOnce(&mut Engine) -> Result<MembershipTransition, EngineError>,
) -> Result<(MembershipTransition, usize), CliError> {
    engine.stage_carry_heads()?;
    let transition = author(engine)?;
    let carried = carry_pending(engine, drive_dir)?;
    Ok((transition, carried))
}

/// Drain the durable carry queue, returning the number carried. The
/// store opens only when obligations are pending.
fn carry_pending(engine: &mut Engine, drive_dir: &Path) -> Result<usize, CliError> {
    if engine.pending_carries()?.is_empty() {
        return Ok(0);
    }
    let store = FsObjectStore::open(drive_dir.to_path_buf())
        .map_err(|error| CliError::Store(error.to_string()))?;
    Ok(engine.carry_pending(&store)?.authored.len())
}

/// Claim an invitation destination before any irreversible step: an
/// existing file is refused outright (no silent overwrite after a
/// membership change), and an uncreatable path fails here with
/// nothing authored. Callers remove the claim when their fallible
/// step fails so a retry starts clean.
fn claim_out(out: &Path) -> Result<fs::File, CliError> {
    if out.exists() {
        return Err(CliError::Usage(
            "invitation destination already exists; remove it or choose another path".into(),
        ));
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(CliError::Usage(
                "invitation destination's parent directory does not exist".into(),
            ));
        }
    }
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|source| CliError::Io {
            path: out.to_path_buf(),
            source,
        })
}

/// Publish a sealed invitation through a claimed file. A write
/// failure past the commit removes the claim and reports the
/// standing state (for invite, the admission; for reissue, nothing
/// changed at all).
fn write_invitation(out: &Path, file: &mut fs::File, bytes: &[u8]) -> Result<(), CliError> {
    if let Err(source) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(out);
        return Err(CliError::Io {
            path: out.to_path_buf(),
            source,
        });
    }
    Ok(())
}

/// Removing the sole owner is valid but terminal (epochs.md): it
/// empties the owner set and no future transition can be authorized.
/// Refuse without explicit confirmation; the protocol stays
/// authoritative and would accept the transition either way.
fn require_last_owner_confirmation(
    engine: &Engine,
    device: &DeviceId,
    yes: bool,
) -> Result<(), CliError> {
    let Some(tip) = engine.membership_log().known_state() else {
        return Ok(());
    };
    let Some(owners) = engine.membership_log().owners_of(&tip.transition_id) else {
        return Ok(());
    };
    if owners.len() == 1 && owners.contains(device) && !yes {
        return Err(CliError::Usage(
            "removing the sole owner permanently ends owner-authorized evolution; pass --yes to confirm"
                .into(),
        ));
    }
    Ok(())
}

/// Members and owners at the canonical tip, one identity per line.
/// Built as a string (not printed) so tests assert the rendering
/// without capturing stdout.
pub(crate) fn member_list_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let readers = log.readers_of(&tip.transition_id).unwrap_or_default();
    let mut out = format!("epoch {} tip {}\n", tip.epoch, tip.transition_id);
    for owner in &owners {
        out.push_str(&format!("owner {owner}\n"));
    }
    for member in &members {
        if !owners.contains(member) {
            out.push_str(&format!("member {member}\n"));
        }
    }
    for reader in &readers {
        out.push_str(&format!("reader {reader}\n"));
    }
    Ok(out)
}

/// Every observed transition in epoch order with its canonical
/// status; frozen conflict epochs are marked. Built as a string so
/// tests assert the rendering without capturing stdout.
pub(crate) fn member_log_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let statuses = log.statuses();
    let frozen = log.frozen_at();
    let mut entries: Vec<(u64, TransitionId)> = statuses
        .keys()
        .filter_map(|id| log.transition(id).map(|t| (t.epoch, *id)))
        .collect();
    entries.sort();
    let mut out = String::new();
    for (epoch, id) in entries {
        let status = statuses.get(&id).expect("statused above");
        let author = log
            .transition(&id)
            .map(|t| t.author.to_string())
            .unwrap_or_else(|| "?".into());
        let frozen_marker = match frozen {
            Some(frozen_epoch) if frozen_epoch == epoch => " frozen",
            _ => "",
        };
        out.push_str(&format!(
            "epoch {epoch} {id} {} author {author}{frozen_marker}\n",
            render_status(status)
        ));
    }
    Ok(out)
}

/// Known tip, frozen conflicts, and held epoch secrets. Knowledge is
/// not possession: a known epoch without its secret authorizes
/// nothing until the capability arrives. Built as a string so tests
/// assert the rendering without capturing stdout.
pub(crate) fn member_status_report(engine: &Engine) -> Result<String, CliError> {
    let log = engine.membership_log();
    let Some(tip) = log.known_state() else {
        return Err(CliError::Engine(
            wyrd_sync::runtime::EngineError::NoCanonicalMembership,
        ));
    };
    let members = log.members_of(&tip.transition_id).unwrap_or_default();
    let owners = log.owners_of(&tip.transition_id).unwrap_or_default();
    let held = engine.held_epochs().map_err(CliError::Engine)?;
    let held_list = held
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let frozen_line = match log.frozen_at() {
        Some(epoch) => {
            // Rival tips: the live contenders the frozen epoch waits
            // on, from the same derivation the resolver validates
            // against — status can never list a rival resolve then
            // refuses. Sorted for stable output.
            let rivals = engine
                .frozen_contenders()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(" ");
            format!("frozen at epoch {epoch}\nrivals: {rivals}")
        }
        None => "frozen: no".into(),
    };
    Ok(format!(
        "epoch {} tip {}\nmembers {} owners {}\n{frozen_line}\nheld secrets: {held_list}\n",
        tip.epoch,
        tip.transition_id,
        members.len(),
        owners.len(),
    ))
}

/// One-word canonical status for the log view; invalid transitions
/// carry their machine reason.
fn render_status(status: &TransitionStatus) -> String {
    match status {
        TransitionStatus::Canonical => "canonical".into(),
        TransitionStatus::Contested => "contested".into(),
        TransitionStatus::Voided => "voided".into(),
        TransitionStatus::Orphaned => "orphaned".into(),
        TransitionStatus::Pending => "pending".into(),
        TransitionStatus::Invalid(reason) => format!("invalid:{reason:?}"),
    }
}
