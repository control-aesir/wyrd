//! Device-local materialization roles: what this device intends to be.
//!
//! A role is replication and retention posture, never replicated drive
//! state. It lives in one `role` file beside the drive's keystore, is
//! read at startup, and must never become a fact-log entry, affect
//! authorization, or alter the replicated snapshot model
//! (`docs/sync-and-peers.md`, Materialization policy vs peer role).
//!
//! A role is a **default**, not an override: explicit pins always mean
//! exactly what they mean today. What the role changes is the baseline
//! everything unpinned is measured against — under `vault`, content
//! `mirror` would leave `REMOTE_ONLY` is effectively retained. That is
//! why [`effective_policy`] takes the stored per-identity state and the
//! role together: there is one effective retention policy, never two
//! sources of truth that can disagree.
//!
//! Role and process are separate (OD-24-R): `vault` the role is what a
//! device is, `wyrd vault` the process is how it is run. Nothing here
//! starts, stops, or gates a serving endpoint.
//!
//! Narrowing (away from `vault`) is a transition, not an edit
//! (OD-24-T): acknowledgement records intent while the effective
//! posture stays `vault` until withdrawal completes. The
//! withdrawal-pending and withdrawal-complete states arrive with the
//! route-publication gate; until then a narrowing device reports
//! [`Transition::NarrowingAcknowledged`] and retains like `vault`.

use std::path::{Path, PathBuf};

use wyrd_sync::runtime::MaterializationState;

use crate::policy::RetentionPolicy;

/// What this device intends to be. Two values deliberately: they are
/// the peer roles `docs/sync-and-peers.md` fixes, not a new axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Participates in live sync, prunable. The default: a device
    /// with no role file behaves exactly as it does today.
    Mirror,
    /// Replicates every object, never prunes.
    Vault,
}

impl Role {
    /// The only accepted spellings. Anything else is a usage error
    /// naming both, so a typo cannot silently become a posture.
    pub fn parse(text: &str) -> Result<Role, RoleError> {
        match text {
            "mirror" => Ok(Role::Mirror),
            "vault" => Ok(Role::Vault),
            other => Err(RoleError::UnknownRole(other.to_string())),
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            Role::Mirror => "mirror",
            Role::Vault => "vault",
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.word())
    }
}

/// Where a narrowing stands. Widening is immediate and carries no
/// transition; only leaving `vault` needs one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// No transition in flight: the configured role is effective.
    Settled,
    /// Narrowing acknowledged (`--yes` recorded): intent is durable
    /// but the effective posture is still `vault`. Withdrawal states
    /// arrive with the route-publication gate.
    NarrowingAcknowledged,
}

impl Transition {
    fn word(self) -> &'static str {
        match self {
            Transition::Settled => "settled",
            Transition::NarrowingAcknowledged => "narrowing-acknowledged",
        }
    }

    fn parse(line: &str) -> Result<Transition, RoleError> {
        match line {
            "transition: narrowing-acknowledged" => Ok(Transition::NarrowingAcknowledged),
            other => Err(RoleError::Malformed {
                detail: format!("unknown transition line {other:?}, want \"transition: narrowing-acknowledged\""),
            }),
        }
    }
}

/// The configured role plus any in-flight narrowing. [`RoleState::effective`]
/// is the posture retention decisions must use — never the configured
/// role directly, or an acknowledged narrowing would silently prune.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleState {
    pub role: Role,
    pub transition: Transition,
}

impl RoleState {
    /// A fresh device: mirror posture, nothing in flight.
    pub fn default_state() -> RoleState {
        RoleState {
            role: Role::Mirror,
            transition: Transition::Settled,
        }
    }

    /// The retention posture in force right now. An acknowledged
    /// narrowing is still `vault` until withdrawal completes — intent
    /// is not observability, and the reconciliation contract retires
    /// obligations, not acknowledgements.
    pub fn effective(self) -> Role {
        match self.transition {
            Transition::Settled => self.role,
            Transition::NarrowingAcknowledged => Role::Vault,
        }
    }

    /// The transition word for status reports.
    pub fn transition_word(self) -> &'static str {
        self.transition.word()
    }
}

/// Whether a role file exists. A missing file is the explicit
/// mirror-shaped default; status reports that distinction so an
/// unset role is never silent.
pub fn is_configured(drive_dir: &Path) -> bool {
    role_path(drive_dir).is_file()
}

/// One effective retention policy from stored per-identity state and
/// the effective role. Explicit pins always win; under `vault` the
/// baseline itself promises retention, so unpinned content is
/// effectively pinned without writing a single policy fact. The
/// stored mapping mirrors [`crate::policy::classify`]: only `Pinned`
/// promises retention, `Cached` carries none.
pub fn effective_policy(stored: MaterializationState, effective: Role) -> RetentionPolicy {
    match stored {
        MaterializationState::Pinned => RetentionPolicy::Pinned,
        MaterializationState::Cached | MaterializationState::RemoteOnly
            if effective == Role::Vault =>
        {
            RetentionPolicy::Pinned
        }
        MaterializationState::Cached | MaterializationState::RemoteOnly => {
            RetentionPolicy::RemoteOnly
        }
    }
}

/// The role file lives beside the keystore (`keystore`, `DRIVE`,
/// `store-key.wrap`): device-local configuration, not drive state.
fn role_path(drive_dir: &Path) -> PathBuf {
    drive_dir.join("role")
}

/// Read this device's role. A missing file is an explicit
/// mirror-shaped default, never an error: it names today's behavior
/// for a device that never opted into anything. A present but
/// unreadable file is an error — a torn write must fail closed, not
/// silently run as `mirror` when the operator set `vault`.
pub fn load(drive_dir: &Path) -> Result<RoleState, RoleError> {
    let bytes = match std::fs::read(role_path(drive_dir)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RoleState::default_state())
        }
        Err(source) => {
            return Err(RoleError::Io {
                path: role_path(drive_dir),
                source,
            })
        }
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| RoleError::Malformed {
        detail: "role file is not UTF-8".to_string(),
    })?;
    let mut lines = text.lines();
    let role =
        Role::parse(lines.next().unwrap_or("").trim()).map_err(|_| RoleError::Malformed {
            detail: "first line must be \"mirror\" or \"vault\"".to_string(),
        })?;
    let transition = match lines.next() {
        None => Transition::Settled,
        Some(line) => Transition::parse(line.trim())?,
    };
    if lines.next().is_some() {
        return Err(RoleError::Malformed {
            detail: "role file carries more than a role and one transition line".to_string(),
        });
    }
    Ok(RoleState { role, transition })
}

/// Persist a role change. Exactly one file is written: no fact, no
/// snapshot, no membership transition, nothing any other device can
/// observe. Atomic (tmp + rename) so a crash leaves the previous
/// role or the new one, never a torn half.
pub fn store(drive_dir: &Path, state: RoleState) -> Result<(), RoleError> {
    let mut text = String::from(state.role.word());
    text.push('\n');
    if state.transition != Transition::Settled {
        text.push_str("transition: ");
        text.push_str(state.transition.word());
        text.push('\n');
    }
    let tmp = drive_dir.join("role.tmp");
    std::fs::write(&tmp, text.as_bytes()).map_err(|source| RoleError::Io {
        path: tmp.clone(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| RoleError::Io {
                path: tmp.clone(),
                source,
            },
        )?;
    }
    std::fs::rename(&tmp, role_path(drive_dir)).map_err(|source| RoleError::Io {
        path: role_path(drive_dir),
        source,
    })?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RoleError {
    #[error("unknown role {0:?}: want \"mirror\" or \"vault\"")]
    UnknownRole(String),
    #[error("unreadable role file: {detail}")]
    Malformed { detail: String },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_role_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wyrd-role-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_file_is_an_explicit_mirror_default() {
        let dir = scratch_role_dir("missing");
        let state = load(&dir).unwrap();
        assert_eq!(state.role, Role::Mirror);
        assert_eq!(state.transition, Transition::Settled);
        assert_eq!(state.effective(), Role::Mirror);
        assert!(!is_configured(&dir));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn store_load_roundtrips_every_state() {
        let dir = scratch_role_dir("roundtrip");
        for state in [
            RoleState {
                role: Role::Mirror,
                transition: Transition::Settled,
            },
            RoleState {
                role: Role::Vault,
                transition: Transition::Settled,
            },
            RoleState {
                role: Role::Mirror,
                transition: Transition::NarrowingAcknowledged,
            },
        ] {
            store(&dir, state).unwrap();
            assert_eq!(load(&dir).unwrap(), state);
        }
        assert!(is_configured(&dir));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn garbage_fails_closed_never_defaults() {
        let dir = scratch_role_dir("garbage");
        for (name, content) in [
            ("empty", ""),
            ("unknown", "archivist\n"),
            ("shouted", "VAULT\n"),
            ("trailing", "vault\n\n"),
            ("bogus-transition", "mirror\ntransition: warp\n"),
        ] {
            std::fs::write(dir.join("role"), content).unwrap();
            assert!(
                load(&dir).is_err(),
                "{name} must fail, never silently default"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn acknowledged_narrowing_stays_vault_effective() {
        let settled_mirror = RoleState {
            role: Role::Mirror,
            transition: Transition::Settled,
        };
        assert_eq!(settled_mirror.effective(), Role::Mirror);
        let acknowledged = RoleState {
            role: Role::Mirror,
            transition: Transition::NarrowingAcknowledged,
        };
        assert_eq!(
            acknowledged.effective(),
            Role::Vault,
            "intent is not observability: posture flips only at withdrawal-complete"
        );
        let settled_vault = RoleState {
            role: Role::Vault,
            transition: Transition::Settled,
        };
        assert_eq!(settled_vault.effective(), Role::Vault);
    }

    #[test]
    fn effective_policy_has_one_baseline_per_role() {
        use MaterializationState::*;
        // Mirror: stored policy is the whole story.
        assert_eq!(
            effective_policy(Pinned, Role::Mirror),
            RetentionPolicy::Pinned
        );
        assert_eq!(
            effective_policy(Cached, Role::Mirror),
            RetentionPolicy::RemoteOnly
        );
        assert_eq!(
            effective_policy(RemoteOnly, Role::Mirror),
            RetentionPolicy::RemoteOnly
        );
        // Vault: explicit pins unchanged, everything else retained —
        // without writing a fact.
        assert_eq!(
            effective_policy(Pinned, Role::Vault),
            RetentionPolicy::Pinned
        );
        assert_eq!(
            effective_policy(Cached, Role::Vault),
            RetentionPolicy::Pinned
        );
        assert_eq!(
            effective_policy(RemoteOnly, Role::Vault),
            RetentionPolicy::Pinned
        );
    }

    #[test]
    fn policy_vocabulary_is_exactly_two_values() {
        // Exhaustive by construction: adding a third RetentionPolicy
        // variant breaks this match AND every consumer, so the CLI
        // can never silently grow the vocabulary the contract fixes
        // at two (docs/sync-and-peers.md: CACHED collapses).
        let words: Vec<&str> = [RetentionPolicy::Pinned, RetentionPolicy::RemoteOnly]
            .iter()
            .map(|policy| match policy {
                RetentionPolicy::Pinned => "PINNED",
                RetentionPolicy::RemoteOnly => "REMOTE_ONLY",
            })
            .collect();
        assert_eq!(words, ["PINNED", "REMOTE_ONLY"]);
    }
}
