//! The `role` command: device-local materialization posture with
//! its renderer and the role-file error mapper (also used by the
//! evict and cache commands, which import it from here).
use crate::commands::cache::cache_quadrant_summary;
use crate::commands::export::open_policy_node;
use crate::CliError;
use std::path::PathBuf;
use wyrd_core::policy::{residency_census_with_role, ResidencyCensus};
use wyrd_sync::keys::DeviceIdentitySecret;
/// Map role-file failures onto CLI errors. A torn or unreadable
/// file fails closed: the operator is told, never silently run as
/// the wrong posture.
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
                "narrowing is already acknowledged and still withdrawing as vault: to start over, widen back to vault first (role set vault), then narrow again with --yes.".into(),
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

/// The configured role, any in-flight narrowing, and the effective
/// retention posture with the numbers to back it: the same census
/// `cache status` reports, because there is one effective policy.
/// While withdrawing, the outstanding count names what is left: own
/// snapshots still routing this device at a peer (zero means serving
/// is still draining — status reads durable state only, so idleness
/// itself is the loop's to observe).
pub(crate) fn role_status_render(
    drive_dir: &std::path::Path,
    state: wyrd_core::role::RoleState,
    census: &ResidencyCensus,
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
    out.push_str(&cache_quadrant_summary(census));
    out
}
