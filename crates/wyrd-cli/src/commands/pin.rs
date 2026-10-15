//! The `pin`, `unpin`, and `evict` commands with their report
//! renderers. Policy only — never fetches, never authors, never
//! touches heads.
use crate::commands::cache::display_policy_path;
use crate::commands::export::open_policy_node;
use crate::commands::role::role_err;
use crate::CliError;
use std::path::PathBuf;
use wyrd_core::policy::{evict_subtree, pin_subtree, unpin_subtree};
use wyrd_sync::keys::DeviceIdentitySecret;
/// Promise retention for a subtree, durably and offline.
pub(crate) fn pin(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        pin_subtree(engine, view, path)?
    };
    print!("{}", pin_render(path, &report));
    Ok(())
}

/// Structured first, rendered below: what one pin promised.
pub(crate) fn pin_render(path: &str, report: &wyrd_core::policy::PinReport) -> String {
    let mut out = format!(
        "pinned {} objects ({} already pinned) across {} files, {} dirs under {}\n",
        report.pinned,
        report.already_pinned,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}

/// Release retention promises under a path, durably and offline.
pub(crate) fn unpin(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        unpin_subtree(engine, view, path)?
    };
    print!("{}", unpin_render(path, &report));
    Ok(())
}

pub(crate) fn unpin_render(path: &str, report: &wyrd_core::policy::UnpinReport) -> String {
    let mut out = format!(
        "unpinned {} objects ({} already unpinned) across {} files, {} dirs under {}\n",
        report.released,
        report.already_unpinned,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    out.push_str("note: released content returns to cacheable policy; bytes stay local\n");
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}

/// Return unpinned content under a path to REMOTE_ONLY policy.
/// Intent only: bytes stay, heads stay.
pub(crate) fn evict(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let state = wyrd_core::role::load(&drive_dir).map_err(role_err)?;
    if state.effective() == wyrd_core::role::Role::Vault {
        return Err(CliError::Usage(
            "role 'vault' forbids eviction: the role promises no pruning. Narrow the role first (role set mirror --yes), or pin explicitly what must stay.".into(),
        ));
    }
    let mut node = open_policy_node(drive_dir, passphrase, identity)?;
    let report = {
        let (engine, view) = node.parts_mut();
        evict_subtree(engine, view, path)?
    };
    print!("{}", evict_render(path, &report));
    Ok(())
}

pub(crate) fn evict_render(path: &str, report: &wyrd_core::policy::EvictReport) -> String {
    let mut out = format!(
        "evicted {} objects ({} already remote-only) across {} files, {} dirs under {}\n",
        report.released,
        report.already_remote,
        report.files,
        report.dirs,
        display_policy_path(path),
    );
    out.push_str("note: eviction releases intent only — no bytes deleted, files that stay fully local keep reading\n");
    if report.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            report.symlinks_skipped
        ));
    }
    out
}
