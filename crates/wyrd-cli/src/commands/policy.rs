//! The `policy` namespace: what this device intends to retain
//! (`pin`/`unpin`/`evict`), what it reports (`status`/`budgets`), and
//! the posture baseline both report against (`role`). One concept —
//! device-local materialization policy — with actions that stay
//! semantically distinct: pin promises, unpin releases, evict changes
//! intent without deleting bytes, and the role sets the baseline the
//! census measures every action against. Policy only — never
//! fetches, never authors, never touches heads, never replicates.
//! Every reader is offline: durable state only, never connects.
use crate::args::{PolicyAction, RoleAction};
use crate::commands::export::open_policy_node;
use crate::drive_config::{CredentialProvenance, LoadedConfig, RelayResolution};
use crate::CliError;
use std::path::{Path, PathBuf};
use wyrd_core::policy::{
    evict_subtree, pin_subtree, residency_census_with_role, unpin_subtree, LocalPresence,
    ResidencyCensus, RetentionPolicy,
};
use wyrd_daemon::{LiveConfig, ResourceBudgets};
use wyrd_sync::keys::DeviceIdentitySecret;

/// One policy invocation. `status` and `budgets` read durable state;
/// the three writes commit one durable policy change each; `role set`
/// writes one local file and no key (the dispatcher in `main.rs`
/// returns it before credential loading).
pub(crate) fn policy(
    drive_dir: PathBuf,
    action: PolicyAction,
    resolution: &RelayResolution,
    config: Option<&LoadedConfig>,
    credential_provenance: &CredentialProvenance,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    match action {
        PolicyAction::Status { path, .. } => policy_status(drive_dir, &path, passphrase, identity),
        PolicyAction::Budgets { .. } => policy_budgets(
            drive_dir,
            resolution,
            config,
            credential_provenance,
            passphrase,
            identity,
        ),
        PolicyAction::Role { action } => match action {
            // Set returns before credential loading, in `main.rs`;
            // the arm exists only because the match is exhaustive.
            RoleAction::Set { .. } => unreachable!("role set returns before credential loading"),
            RoleAction::Status { .. } => role_status(drive_dir, passphrase, identity),
        },
        PolicyAction::Pin { path, .. } => pin(drive_dir, &path, passphrase, identity),
        PolicyAction::Unpin { path, .. } => unpin(drive_dir, &path, passphrase, identity),
        PolicyAction::Evict { path, .. } => evict(drive_dir, &path, passphrase, identity),
    }
}

/// The unified projection: one census, read once, renders the role
/// posture it was measured against and the per-file table it
/// produced. The census and the posture cannot disagree, because
/// there is one read of each — not two helpers each re-deriving
/// state.
fn policy_status(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let node = open_policy_node(drive_dir.clone(), passphrase, identity)?;
    let state = wyrd_core::role::load(&drive_dir).map_err(role_err)?;
    let role = state.effective();
    let (engine, view) = node.parts();
    let census = residency_census_with_role(engine, view, path, role)?;
    let outstanding = wyrd_core::role::withdrawal_outstanding(engine)?;
    print!(
        "{}",
        policy_status_render(
            &role_section_render(&drive_dir, state, outstanding),
            path,
            &census
        )
    );
    Ok(())
}

/// Device totals over reachable content plus the budgets that bound
/// retention and fetch. Reads durable state only.
fn policy_budgets(
    drive_dir: PathBuf,
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
    let (engine, view) = node.parts();
    let census = residency_census_with_role(engine, view, "", role)?;
    // Three walks at report time, never cached: the enforced
    // object-store count plus the two observational dimensions.
    let retained_content = view
        .store_read()
        .map_err(|error| CliError::Store(error.to_string()))?
        .retained_bytes()
        .map_err(|error| CliError::Store(error.to_string()))?;
    // One budgets read for the whole report: the quota line and the
    // budget lines below must come from the same value, or the
    // report can disagree with itself.
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
    print!("{}", policy_budgets_render(&census, &accounting, &budgets));
    print!(
        "{}",
        config_section_render(resolution, config, credential_provenance)
    );
    Ok(())
}

/// Map role-file failures onto CLI errors. A torn or unreadable file
/// fails closed: the operator is told, never silently run as the
/// wrong posture.
pub(crate) fn role_err(error: wyrd_core::role::RoleError) -> CliError {
    match error {
        wyrd_core::role::RoleError::UnknownRole(_)
        | wyrd_core::role::RoleError::Malformed { .. } => CliError::Usage(error.to_string()),
        wyrd_core::role::RoleError::Io { path, source } => CliError::Io { path, source },
    }
}

/// Set this device's materialization role without touching keys:
/// exactly one local file is written — no fact, no snapshot, no
/// membership transition, nothing any other device can observe.
pub(crate) fn role_set(drive_dir: PathBuf, role: String, yes: bool) -> Result<(), CliError> {
    use wyrd_core::role::{Role, RoleState, Transition};
    let target = Role::parse(&role).map_err(|error| CliError::Usage(error.to_string()))?;
    let current = wyrd_core::role::load(&drive_dir).map_err(role_err)?;
    if current.transition == Transition::Settled && current.role == target {
        println!("role already {target} (settled); no change");
        return Ok(());
    }
    if target == Role::Mirror && current.effective() == Role::Vault {
        if matches!(
            current.transition,
            Transition::NarrowingAcknowledged | Transition::WithdrawalPending
        ) {
            return Err(CliError::Usage(
                "narrowing is already acknowledged and still withdrawing as vault: to start over, widen back to vault first (policy role set vault), then narrow again with --yes.".into(),
            ));
        }
        if !yes {
            return Err(CliError::Usage(
                "narrowing away from the vault role requires --yes: leaving vault stops being a provider, and that must be explicit. Acknowledgement records intent only; effective posture stays vault until withdrawal completes.".into(),
            ));
        }
        let state = RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        };
        wyrd_core::role::store(&drive_dir, state).map_err(role_err)?;
        println!(
            "narrowing acknowledged: configured mirror, effective still vault until withdrawal completes\nnote: the live loop withdraws on its next passes (route-less announcements, then settled mirror); this device retains like vault until then"
        );
        return Ok(());
    }
    let state = RoleState {
        role: target,
        transition: Transition::Settled,
    };
    wyrd_core::role::store(&drive_dir, state).map_err(role_err)?;
    println!("role set to {target}; effective immediately");
    Ok(())
}

/// Report the configured role, any in-flight narrowing, and the
/// effective retention posture. Reads durable state only; never
/// connects, never mutates.
pub(crate) fn role_status(
    drive_dir: PathBuf,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let state = wyrd_core::role::load(&drive_dir).map_err(role_err)?;
    let node = open_policy_node(drive_dir.clone(), passphrase, identity)?;
    let (engine, view) = node.parts();
    let census = residency_census_with_role(engine, view, "", state.effective())?;
    let outstanding = wyrd_core::role::withdrawal_outstanding(engine)?;
    print!(
        "{}",
        role_status_render(&drive_dir, state, &census, outstanding)
    );
    Ok(())
}

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
/// Intent only: bytes stay, heads stay. Eviction never silently
/// changes what a pin means: a pinned subtree refuses, and the
/// vault role refuses the whole command.
pub(crate) fn evict(
    drive_dir: PathBuf,
    path: &str,
    passphrase: &str,
    identity: DeviceIdentitySecret,
) -> Result<(), CliError> {
    let state = wyrd_core::role::load(&drive_dir).map_err(role_err)?;
    if state.effective() == wyrd_core::role::Role::Vault {
        return Err(CliError::Usage(
            "role 'vault' forbids eviction: the role promises no pruning. Narrow the role first (policy role set mirror --yes), or pin explicitly what must stay.".into(),
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

/// The effective deployment configuration behind a `policy budgets`
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

/// The posture block: configured role, transition, effective, and
/// the notes that qualify them. Shared by `policy status` and
/// `policy role status` so the two projections cannot drift — one
/// renderer, one meaning.
pub(crate) fn role_section_render(
    drive_dir: &Path,
    state: wyrd_core::role::RoleState,
    outstanding: usize,
) -> String {
    use wyrd_core::role::Transition;
    let mut out = format!(
        "role: {}\ntransition: {}\neffective: {}\n",
        state.role,
        state.transition_word(),
        state.effective(),
    );
    if !wyrd_core::role::is_configured(drive_dir) {
        out.push_str(
            "note: no role file: mirror names current behavior (prunable), not a choice\n",
        );
    }
    if state.transition == Transition::NarrowingAcknowledged {
        out.push_str(
            "note: narrowing acknowledged; retains like vault until withdrawal completes\n",
        );
    }
    if state.transition == Transition::WithdrawalPending {
        out.push_str(&format!(
            "note: withdrawal pending: {outstanding} own snapshot(s) still route this device at a peer; retains like vault until route publication drains and serving idles\n",
        ));
    }
    out
}

/// `policy role status`: the posture block plus the quadrant totals
/// it implies. The same census `policy status` reads, rendered
/// without the table — the role report is the posture report, and
/// the numbers backing it are the ones the status report prints.
pub(crate) fn role_status_render(
    drive_dir: &Path,
    state: wyrd_core::role::RoleState,
    census: &ResidencyCensus,
    outstanding: usize,
) -> String {
    let mut out = role_section_render(drive_dir, state, outstanding);
    out.push_str(&policy_quadrant_summary(census));
    out
}

/// `policy status`: the posture block, then one row per reachable
/// file plus quadrant totals. The caller computes one census; this
/// renders it once, under the posture it was read against.
pub(crate) fn policy_status_render(
    role_block: &str,
    path: &str,
    census: &ResidencyCensus,
) -> String {
    let mut out = String::from(role_block);
    out.push_str(&format!(
        "policy status under {}\nPOLICY       LOCAL    PATH\n",
        display_policy_path(path)
    ));
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
    out.push_str(&policy_quadrant_summary(census));
    if census.symlinks_skipped > 0 {
        out.push_str(&format!(
            "note: {} symlinks skipped (a link names no content of its own)\n",
            census.symlinks_skipped
        ));
    }
    out
}

pub(crate) fn policy_quadrant_summary(census: &ResidencyCensus) -> String {
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
pub(crate) fn policy_budgets_render(
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
        "policy budgets (reachable content)\npinned files: {pinned_files}\npinned chunks: {pinned_chunks}\n",
    );
    out.push_str(&policy_quadrant_summary(census));
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

/// Measured byte dimensions behind `policy budgets`' retention
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
