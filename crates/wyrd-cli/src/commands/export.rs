//! The `export` command plus the shared offline policy-node
//! opener. Export itself is offline by construction; the opener
//! also serves the pin, role, and cache commands, which import
//! it from here.
use crate::CliError;
use std::path::PathBuf;
use wyrd_core::export::export_tree;
use wyrd_daemon::core::RuntimeMaterialization;
use wyrd_daemon::fuse::DriveView;
use wyrd_daemon::WyrdNode;
use wyrd_format::FsObjectStore;
use wyrd_sync::keys::DeviceIdentitySecret;
use wyrd_sync::runtime::Engine;
/// Export the drive's namespace to a plain tree. The open path
/// mirrors mount's preamble (keystore, object store, live heads)
/// minus everything export refuses to need: no diagnostics file, no
/// serving endpoint, no bulk source, no mailbox, no FUSE session.
/// The composed view type arrives through the daemon's surface, so
/// this host never names the view crate directly.
pub(crate) fn export(
    drive_dir: PathBuf,
    out_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut daemon: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> = WyrdNode::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    daemon.refresh_live_heads()?;
    let report = export_tree(daemon.view(), &out_dir)?;
    eprintln!(
        "exported {} files, {} dirs, {} symlinks ({} conflicts, {} bytes) to {}",
        report.files,
        report.dirs,
        report.symlinks,
        report.conflicts,
        report.bytes,
        out_dir.display()
    );
    Ok(())
}

/// Offline policy node: the engine plus its read view over the
/// drive's own store, heads installed once up front. Every
/// pin/unpin/evict/cache command composes this shape — no loop, no
/// mailbox, no bulk source — so policy changes never depend on
/// network availability. Heads install once and the walk never
/// re-refreshes: one invocation observes one generation, and a
/// concurrent local write cannot mix generations into it.
type PolicyNode = WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>>;

pub(crate) fn open_policy_node(
    drive_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<PolicyNode, CliError> {
    let engine = Engine::open_keystore(drive_dir.clone(), passphrase, identity)?;
    let mut node: PolicyNode = WyrdNode::new(
        engine,
        FsObjectStore::open(drive_dir.clone())
            .map_err(|error| CliError::Store(error.to_string()))?,
    )?;
    node.refresh_live_heads()?;
    Ok(node)
}
