//! The `cache` command with its residency renderers and the
//! `RetentionAccounting` measurement behind `cache policy`.
//! Read-only over durable state; never connects, never mutates.
use crate::args::CacheAction;
use crate::commands::export::open_policy_node;
use crate::commands::role::role_err;
use crate::drive_config::{CredentialProvenance, LoadedConfig, RelayResolution};
use crate::CliError;
use std::path::PathBuf;
use wyrd_core::policy::{
    residency_census_with_role, LocalPresence, ResidencyCensus, RetentionPolicy,
};
use wyrd_daemon::{LiveConfig, ResourceBudgets};
use wyrd_sync::keys::DeviceIdentitySecret;
/// Report residency: per-file policy vs presence, or device totals
/// plus the effective budgets.
pub(crate) fn cache(
    drive_dir: PathBuf,
    action: CacheAction,
    resolution: &RelayResolution,
    config: Option<&LoadedConfig>,
    credential_provenance: &CredentialProvenance,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let node = open_policy_node(drive_dir.clone(), passphrase, identity)?;
    let role = wyrd_core::role::load(&drive_dir)
        .map_err(role_err)?
        .effective();
    match action {
        CacheAction::Status { path } => {
            let (engine, view) = node.parts();
            let census = residency_census_with_role(engine, view, &path, role)?;
            print!("{}", cache_status_render(&path, &census));
            Ok(())
        }
        CacheAction::Policy => {
            let (engine, view) = node.parts();
            let census = residency_census_with_role(engine, view, "", role)?;
            // Three walks at report time, never cached: the enforced
            // object-store count plus the two observational dimensions.
            let retained_content = view
                .store_read()
                .map_err(|error| CliError::Store(error.to_string()))?
                .retained_bytes()
                .map_err(|error| CliError::Store(error.to_string()))?;
            // One budgets read for the whole report: the quota line and
            // the budget lines below must come from the same value, or
            // the report can disagree with itself.
            let budgets = LiveConfig::for_local_sync().budgets;
            let accounting = RetentionAccounting {
                retained_content,
                fact_log: engine.fact_log_bytes()?,
                sync_vault: engine
                    .vault()
                    .resident_bytes()
                    .map_err(|error| CliError::Store(error.to_string()))?,
                quota: budgets.retained_bytes_quota,
            };
            print!("{}", cache_policy_render(&census, &accounting, &budgets));
            print!(
                "{}",
                config_section_render(resolution, config, credential_provenance)
            );
            Ok(())
        }
    }
}

/// The effective deployment configuration behind a `cache policy`
/// report: which file was read (or that none was), where the relay
/// list came from, and which surface each credential path came
/// from — so the operator answers "what is this drive actually
/// configured with" without reading the file. Pure over the
/// resolved values, next to its only consumer.
pub(crate) fn config_section_render(
    resolution: &RelayResolution,
    config: Option<&LoadedConfig>,
    credential_provenance: &CredentialProvenance,
) -> String {
    let mut out = String::from("configuration:\n");
    match config {
        Some(loaded) => out.push_str(&format!("  file: {}\n", loaded.path.display())),
        None => out.push_str("  file: none (no configuration file)\n"),
    }
    out.push_str(&format!(
        "  relays: {} ({})\n",
        resolution.relays.len(),
        resolution.source.word(),
    ));
    out.push_str(&format!(
        "  identity_file: {}\n",
        CredentialProvenance::word(credential_provenance.identity_from_file),
    ));
    out.push_str(&format!(
        "  passphrase_file: {}\n",
        CredentialProvenance::word(credential_provenance.passphrase_from_file),
    ));
    out
}

/// Empty path addresses the drive root; render it as `/` so the
/// report reads like a path instead of an empty string.
pub(crate) fn display_policy_path(path: &str) -> &str {
    if path.is_empty() {
        "/"
    } else {
        path
    }
}

pub(crate) fn policy_word(policy: RetentionPolicy) -> &'static str {
    match policy {
        RetentionPolicy::Pinned => "PINNED",
        RetentionPolicy::RemoteOnly => "REMOTE_ONLY",
    }
}

pub(crate) fn presence_word(local: LocalPresence) -> &'static str {
    match local {
        LocalPresence::Present => "PRESENT",
        LocalPresence::Absent => "ABSENT",
    }
}

/// Structured data first; the CLI renders text, future consumers
/// render their own. One row per reachable file plus quadrant
/// totals — the rows name what is held, the totals name what it
/// amounts to.
pub(crate) fn cache_status_render(path: &str, census: &ResidencyCensus) -> String {
    let mut out = format!(
        "cache status under {}\nPOLICY       LOCAL    PATH\n",
        display_policy_path(path)
    );
    for file in &census.files {
        out.push_str(&format!(
            "{:<12} {:<8} {}\n",
            policy_word(file.policy),
            presence_word(file.local),
            file.path
        ));
    }
    for conflict in &census.conflicts {
        out.push_str(&format!("{:<12} {:<8} {}\n", "CONFLICT", "-", conflict));
    }
    out.push_str(&cache_quadrant_summary(census));
    if census.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            census.symlinks_skipped
        ));
    }
    out
}

pub(crate) fn cache_quadrant_summary(census: &ResidencyCensus) -> String {
    format!(
        "files: {} (PINNED/PRESENT: {}, PINNED/ABSENT: {}, REMOTE_ONLY/PRESENT: {}, REMOTE_ONLY/ABSENT: {}), dirs: {}\n",
        census.files.len(),
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present),
        census.quadrant(RetentionPolicy::Pinned, LocalPresence::Absent),
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Present),
        census.quadrant(RetentionPolicy::RemoteOnly, LocalPresence::Absent),
        census.dirs,
    )
}

/// Device totals over reachable content plus the budgets that
/// bound retention and fetch. The budgets are the live loop's own
/// (`for_local_sync`, the same config mount runs): what the report
/// calls effective is what the daemon enforces, not a parallel
/// copy. Only the retention- and fetch-relevant bounds print here;
/// the full table lives in `docs/resource-limits.md`.
pub(crate) fn cache_policy_render(
    census: &ResidencyCensus,
    accounting: &RetentionAccounting,
    budgets: &ResourceBudgets,
) -> String {
    let pinned_files = census.quadrant(RetentionPolicy::Pinned, LocalPresence::Present)
        + census.quadrant(RetentionPolicy::Pinned, LocalPresence::Absent);
    // Per identity, deduplicated across files that share chunks: a
    // chunk pinned through two paths is one promise, not two.
    let pinned_chunks = census.pinned_chunk_union().len();
    let mut out = format!(
        "cache policy (reachable content)\npinned files: {pinned_files}\npinned chunks: {pinned_chunks}\n",
    );
    out.push_str(&cache_quadrant_summary(census));
    // Totals silently skip conflicted subtrees, so name the gap:
    // without this the numbers read as complete on a drive where
    // whole paths were never walked. One row per path, like the
    // status report, instead of one unbounded joined line.
    if !census.conflicts.is_empty() {
        out.push_str(&format!(
            "conflicts: {} skipped (never walked):\n",
            census.conflicts.len()
        ));
        for conflict in &census.conflicts {
            out.push_str(&format!("  {conflict}\n"));
        }
    }
    out.push_str("budgets (effective):\n");
    match accounting.quota {
        Some(quota) => out.push_str(&format!("  retained_bytes_quota: {quota}\n")),
        None => out.push_str("  retained_bytes_quota: unlimited\n"),
    }
    out.push_str(&format!(
        "  max_admit_per_pass: {}\n  max_pending_wants: {}\n  max_quarantine_per_pass: {}\n",
        budgets.max_admit_per_pass, budgets.max_pending_wants, budgets.max_quarantine_per_pass,
    ));
    // The retention breakdown: one row per resident dimension, each
    // labelled with whether it backs enforcement or merely observes.
    // `retained content` is the enforcement quantity — the number the
    // ceiling is compared against. The fact log and the sync vault
    // are resident but unenforced (auxiliary growth): folding them
    // into the enforced number would silently widen what a refusal
    // rejects, so they report separately and the total is labelled
    // observational. See the retained / resident / auxiliary terms in
    // `docs/storage-growth.md`.
    let total = accounting
        .retained_content
        .saturating_add(accounting.fact_log)
        .saturating_add(accounting.sync_vault);
    out.push_str("retention accounting (bytes):\n");
    out.push_str(&format!(
        "  retained content: {} (quota-enforced)\n",
        accounting.retained_content
    ));
    out.push_str(&format!(
        "  fact log: {} (observational)\n",
        accounting.fact_log
    ));
    out.push_str(&format!(
        "  sync vault: {} (observational)\n",
        accounting.sync_vault
    ));
    out.push_str(&format!("  total accounted: {total} (observational)\n"));
    // No implicit ceiling: with no configured quota the report advises
    // one instead of applying one. The recommendation is explicitly
    // advisory and non-authoritative — a starting point for the
    // operator's decision, never a default by another name. A quota is
    // an operator-selected refusal boundary, not an implicit product
    // policy: anything at or below current retention refuses every
    // write, so the advice starts there.
    if accounting.quota.is_none() {
        out.push_str(&format!(
            "  advisory ceiling (non-authoritative): no lower than {} \
             (current retention); no default is applied\n",
            accounting.retained_content
        ));
    }
    out
}

/// Measured byte dimensions behind `cache policy`'s retention
/// breakdown: the enforcement quantity plus the two resident-but-
/// unenforced dimensions. Measured at report time from the mounted
/// store, the fact log, and the vault — three walks, never cached,
/// so the report cannot disagree with the disk.
pub(crate) struct RetentionAccounting {
    /// Object-store bytes: the quota-enforced quantity.
    pub(crate) retained_content: u64,
    /// Fact-log commit bytes: resident, observational.
    pub(crate) fact_log: u64,
    /// Sealed vault representations: resident, observational.
    pub(crate) sync_vault: u64,
    /// The effective quota, if one is configured.
    pub(crate) quota: Option<u64>,
}
