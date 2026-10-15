//! The `snapshot` command: merge, recover, listings, and plans.
//! Owns the snapshot runner, the merge-path guards, and the
//! snapshot/recovery/classification renderers; the dispatcher in
//! `main.rs` calls in.

use crate::args::{RecoverAction, SnapshotAction};
use crate::commands::device::{parse_content_id, parse_snapshot_id};
use crate::CliError;
use std::collections::BTreeMap;
use std::path::PathBuf;
use wyrd_format::FsObjectStore;
use wyrd_format::{SnapshotId, RECOVERY_FLAG};
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::{Engine, EngineError, MergeSelection};
/// Inspect snapshots and merge conflicted heads offline over the
/// keystore. Merging authors one snapshot with ordinary member
/// authority (the engine enforces eligibility and the merge-spec
/// contract, never the CLI) and queues the usual announcements for
/// the next mounted sync.
pub(crate) fn snapshot(
    drive_dir: PathBuf,
    action: SnapshotAction,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    match action {
        SnapshotAction::List => {
            print!("{}", snapshot_list_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Heads => {
            print!("{}", snapshot_heads_report(&engine)?);
            Ok(())
        }
        SnapshotAction::Plan { heads } => {
            let selected = select_merge_heads(&engine, &heads)?;
            let store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let plan = engine
                .merge_plan(&store, selected)
                .map_err(map_merge_error)?;
            print!("{}", snapshot_plan_report(&plan));
            Ok(())
        }
        SnapshotAction::Merge {
            heads,
            default,
            takes,
            drops,
        } => {
            // Sources default to every live head; explicit ids narrow
            // to a subset. Sorted ascending, so `@N` numbers the
            // selection in SnapshotId byte order.
            let selected = select_merge_heads(&engine, &heads)?;
            let resolve_ref = |reference: &str| -> Result<SnapshotId, CliError> {
                let number: usize = reference
                    .strip_prefix('@')
                    .and_then(|number| number.parse().ok())
                    .filter(|number| *number >= 1)
                    .ok_or_else(|| {
                        CliError::Usage(format!("head reference must be @N, got {reference:?}"))
                    })?;
                selected.get(number - 1).copied().ok_or_else(|| {
                    CliError::Usage(format!(
                        "@{number} names no selected head: {} selected",
                        selected.len()
                    ))
                })
            };
            let default = default
                .map(|reference| resolve_ref(&reference))
                .transpose()?;
            let mut spec = BTreeMap::new();
            for take in &takes {
                let (path, reference) = take.split_once('=').ok_or_else(|| {
                    CliError::Usage(format!("--take must be path=@N, got {take:?}"))
                })?;
                let id = resolve_ref(reference)?;
                if spec
                    .insert(check_merge_path(path)?, MergeSelection::Take(id))
                    .is_some()
                {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            for drop in &drops {
                let path = check_merge_path(drop)?;
                if spec.insert(path.clone(), MergeSelection::Absent).is_some() {
                    return Err(CliError::Usage(format!(
                        "duplicate selection for path {path:?}"
                    )));
                }
            }
            let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                .map_err(|error| CliError::Store(error.to_string()))?;
            let merged = engine
                .merge_heads(&mut store, selected, default, spec)
                .map_err(map_merge_error)?;
            let parents = merged
                .snapshot()
                .parents
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            println!(
                "merged {} at epoch {} (parents {parents})",
                merged.snapshot().snapshot_id(),
                merged.snapshot().epoch,
            );
            Ok(())
        }
        SnapshotAction::Recover { action } => match action {
            RecoverAction::Plan { from } => {
                let from = parse_snapshot_id(&from)?;
                let store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let plan = engine.recovery_plan(&store, from)?;
                print!("{}", recovery_plan_report(&plan));
                Ok(())
            }
            RecoverAction::Run {
                from,
                takes,
                all,
                contents,
            } => {
                check_recovery_owner(&engine)?;
                if all && !takes.is_empty() {
                    return Err(CliError::Usage(
                        "--all grafts the whole source tree: drop the --take lines".into(),
                    ));
                }
                let from = parse_snapshot_id(&from)?;
                let mut checked = Vec::with_capacity(takes.len());
                for take in &takes {
                    checked.push(check_recover_path(take)?);
                }
                let mut ids = Vec::with_capacity(contents.len());
                for content in &contents {
                    ids.push(parse_content_id(content)?);
                }
                let mut store = FsObjectStore::open(drive_dir.to_path_buf())
                    .map_err(|error| CliError::Store(error.to_string()))?;
                let grafted = engine.recover(&mut store, from, &checked, all, &ids)?;
                let parents = grafted
                    .snapshot()
                    .parents
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ");
                println!(
                    "recovered {} at epoch {} (parents {parents})",
                    grafted.snapshot().snapshot_id(),
                    grafted.snapshot().epoch,
                );
                Ok(())
            }
        },
    }
}

/// Resolve merge sources: every live head by default, or an
/// explicit id subset. Sorted ascending, so `@N` numbers the
/// selection in SnapshotId byte order — the basis `merge` and
/// `plan` share.
pub(crate) fn select_merge_heads(
    engine: &Engine,
    heads: &[String],
) -> Result<Vec<SnapshotId>, CliError> {
    let mut selected: Vec<SnapshotId> = if heads.is_empty() {
        engine
            .live_heads()?
            .iter()
            .map(|head| head.snapshot().snapshot_id())
            .collect()
    } else {
        heads
            .iter()
            .map(|head| parse_snapshot_id(head))
            .collect::<Result<_, _>>()?
    };
    selected.sort();
    Ok(selected)
}

/// Where snapshot merging stalls on a membership conflict: the
/// operator resolves with `member resolve`, never by adding heads.
pub(crate) fn frozen_merge_hint(epoch: u64) -> String {
    format!(
        "membership frozen at epoch {epoch}: resolve it with `member resolve` \
        (see `member status`) before merging snapshots"
    )
}

/// Map a merge refusal that names the membership freeze to usage
/// guidance; every other engine verdict passes through untouched.
pub(crate) fn map_merge_error(error: EngineError) -> CliError {
    match error {
        EngineError::MergeBlockedByFreeze(epoch) => CliError::Usage(frozen_merge_hint(epoch)),
        _ => CliError::Engine(error),
    }
}

/// The OD-15-5 presentation check: refuse before the operator
/// composes a selection when this device is not the current
/// canonical owner. Reads the same membership projection the
/// engine enforces, and the engine still wins any race — a pass
/// here never authorizes anything.
pub(crate) fn check_recovery_owner(engine: &Engine) -> Result<(), CliError> {
    let log = engine.membership_log();
    let known = log
        .known_state()
        .ok_or(EngineError::NoCanonicalMembership)?;
    match log.owners_of(&known.transition_id) {
        Some(owners) if owners.len() == 1 && owners.contains(&engine.device()) => Ok(()),
        _ => Err(CliError::Engine(EngineError::RecoveryNotOwner)),
    }
}

/// One merge-spec path: a root entry name. v0 merges at root-entry
/// granularity (a conflicting subtree is taken or dropped whole),
/// so anything deeper is refused at the argument boundary.
pub(crate) fn check_merge_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "merge paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// One recovery-selection path: the same root-entry granularity
/// as the merge spec, so a grafted subtree travels whole.
pub(crate) fn check_recover_path(path: &str) -> Result<String, CliError> {
    if path.is_empty() || path.contains('/') {
        return Err(CliError::Usage(format!(
            "recover paths are root entries, got {path:?}"
        )));
    }
    Ok(path.to_owned())
}

/// Live heads with their `@N` merge numbers, ascending by id —
/// the same order the `name@N` conflict siblings use. Built as a
/// string so tests assert the rendering without capturing stdout.
pub(crate) fn snapshot_list_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.live_heads()?;
    if heads.is_empty() {
        return Ok("live heads: none\n".into());
    }
    let mut out = String::from("live heads:\n");
    for (number, head) in heads.iter().enumerate() {
        let snapshot = head.snapshot();
        out.push_str(&format!(
            "@{} {} epoch {} author {} tree {} parents {}{}\n",
            number + 1,
            snapshot.snapshot_id(),
            snapshot.epoch,
            snapshot.author,
            snapshot.tree,
            snapshot.parents.len(),
            recovery_marker(snapshot.flags()),
        ));
    }
    Ok(out)
}

/// Every DAG head with its authorization classification; eligible
/// heads carry their `@N` merge numbers. Built as a string so tests
/// assert the rendering without capturing stdout.
pub(crate) fn snapshot_heads_report(engine: &Engine) -> Result<String, CliError> {
    let heads = engine.snapshot_heads()?;
    if heads.is_empty() {
        return Ok("heads: none\n".into());
    }
    let mut eligible: Vec<SnapshotId> = heads
        .iter()
        .filter(|head| {
            matches!(
                head.classification,
                wyrd_sync::authorization::Classification::Eligible
            )
        })
        .map(|head| head.id)
        .collect();
    eligible.sort();
    let mut out = String::from("heads:\n");
    for head in &heads {
        let number = eligible
            .iter()
            .position(|id| *id == head.id)
            .map(|number| format!(" @{}", number + 1))
            .unwrap_or_default();
        out.push_str(&format!(
            "{}{} {} epoch {}{}\n",
            head.id,
            number,
            render_classification(&head.classification),
            head.epoch,
            recovery_marker(head.flags),
        ));
    }
    Ok(out)
}

/// Preview a merge without authoring: one row per root path over
/// the plan's `@N` basis, naming each head's version. Agreed paths
/// take themselves; conflicted rows are the `--take` lines the
/// merge still needs. Built as a string so tests assert the
/// rendering without capturing stdout.
pub(crate) fn snapshot_plan_report(plan: &wyrd_sync::runtime::MergePlan) -> String {
    use wyrd_format::EntryContent;
    let mut out = format!("merge plan ({} heads):\n", plan.heads.len());
    for path in &plan.paths {
        if path.agreed() {
            out.push_str(&format!("{}: agreed\n", path.path));
            continue;
        }
        let mut versions = Vec::new();
        for (number, head) in plan.heads.iter().enumerate() {
            let version = match path.versions.get(head).and_then(|version| version.as_ref()) {
                None => "absent".to_owned(),
                Some(entry) => match &entry.content {
                    EntryContent::File { size, chunks, .. } => {
                        format!("file:{size}B,{}chunks", chunks.len())
                    }
                    EntryContent::Dir { .. } => "dir".to_owned(),
                    EntryContent::Symlink { .. } => "symlink".to_owned(),
                },
            };
            versions.push(format!("@{}={}", number + 1, version));
        }
        out.push_str(&format!(
            "{}: conflicted {}\n",
            path.path,
            versions.join(" ")
        ));
    }
    out
}

/// The recovery audit marker: a recovery-flagged snapshot names
/// itself in both head views, so grafts stay visible as long as the
/// snapshot is listed at all.
pub(crate) fn recovery_marker(flags: u8) -> &'static str {
    if flags & RECOVERY_FLAG != 0 {
        " recovery"
    } else {
        ""
    }
}

/// Preview a recovery without authoring: one row per source root
/// path with its status, so the operator sees what is graftable,
/// what is already live, and what is gone. Built as a string so
/// tests assert the rendering without capturing stdout.
pub(crate) fn recovery_plan_report(plan: &wyrd_sync::runtime::RecoveryPlan) -> String {
    use wyrd_sync::runtime::RecoveryStatus;
    let mut out = format!("recovery plan (from {}):\n", plan.from);
    for row in &plan.paths {
        let status = match row.status {
            RecoveryStatus::Ready => "ready".to_owned(),
            RecoveryStatus::AlreadyLive => {
                "already-live: a current head holds this path — recovery is the wrong verb"
                    .to_owned()
            }
            RecoveryStatus::Undecryptable => {
                "undecryptable: no held epoch decrypts these bytes".to_owned()
            }
            RecoveryStatus::Missing => "missing: bytes are not local".to_owned(),
        };
        out.push_str(&format!("{}: {status}\n", row.path));
    }
    out
}

/// One-word head class for the heads view; parked and rejected
/// heads carry their machine reason.
pub(crate) fn render_classification(class: &wyrd_sync::authorization::Classification) -> String {
    use wyrd_sync::authorization::Classification;
    match class {
        Classification::Eligible => "eligible".into(),
        Classification::CanonicalHistory => "canonical-history".into(),
        Classification::Superseded => "superseded".into(),
        Classification::Stranded => "stranded".into(),
        Classification::Voided => "voided".into(),
        Classification::Pending(pendency) => format!("pending:{pendency:?}"),
        Classification::Rejected(rejection) => format!("rejected:{rejection:?}"),
    }
}
