//! The workspace dependency DAG is a load-bearing architectural invariant:
//! layers depend downward only (`wyrd-format → wyrd-sync → wyrd-core →
//! presentation`), so the Phase 1 extraction cannot smuggle a backward
//! edge while staying green. This module checks every member's
//! `[dependencies]` against the declared policy and fails closed on any
//! crate the policy does not know: a new member or a new edge is a
//! deliberate policy edit, never an accident.
//!
//! Only production `[dependencies]` are checked. `[dev-dependencies]`
//! stay exempt on purpose: they never ship, and test harnesses
//! legitimately reach further (in-process relays, fast-KDF profiles).
//!
//! Two rules need source, not manifests, and live here as well:
//! `nostr` use inside `wyrd-core` must stay inside one subsystem
//! directory (the mailbox decision), because manifests cannot scope a
//! dependency to a module.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// A normal `[dependencies]` edge set for one member: crate name to the
/// raw manifest value (kept for future diagnostics; only the keys matter
/// today).
type DepSet = BTreeMap<String, toml::Value>;

/// Policy for one workspace member. `workspace_allow` is the exact set
/// of `wyrd-*` crates it may depend on; `external_deny` names
/// third-party crates it must never gain, with the reason recorded at
/// the call site. Anything not listed here fails closed.
struct MemberPolicy {
    workspace_allow: &'static [&'static str],
    external_deny: &'static [&'static str],
}

fn policy_for(member: &str) -> Option<MemberPolicy> {
    match member {
        // Hard rule from AGENTS.md: plaintext world, five crates max.
        "wyrd-format" => Some(MemberPolicy {
            workspace_allow: &[],
            external_deny: &[],
        }),
        // Protocol machinery: format below, everything else forbidden
        // upward or sideways.
        "wyrd-sync" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format"],
            external_deny: &[],
        }),
        // The embeddable node: sync and format below; never presentation
        // (fuser), argument parsing (clap), POSIX errno mapping (libc),
        // or process-signal handling. The `wyrd-core` edge on `wyrd-fuse`
        // is allowed now so Phase 2 can point the adapter at the
        // provider-neutral API without a policy edit.
        "wyrd-core" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync"],
            external_deny: &["fuser", "clap", "libc", "signal-hook", "nix"],
        }),
        "wyrd-fuse" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-core"],
            external_deny: &[],
        }),
        // The composer and process host: everything below, never the CLI
        // (presentation depends on the host's public surface, not the
        // reverse) and never the contract suite.
        "wyrd-daemon" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync", "wyrd-fuse", "wyrd-core"],
            external_deny: &[],
        }),
        // Thin parsing over the node API: may drive core and the
        // daemon's public host surface, never the view crate or raw
        // FUSE directly.
        "wyrd-cli" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync", "wyrd-core", "wyrd-daemon"],
            external_deny: &["fuser"],
        }),
        // The suite itself: leaf, depends on every crate, and the
        // reverse edge is checked separately below.
        "wyrd-contracts" => Some(MemberPolicy {
            workspace_allow: &[
                "wyrd-format",
                "wyrd-sync",
                "wyrd-fuse",
                "wyrd-core",
                "wyrd-daemon",
                "wyrd-cli",
            ],
            external_deny: &[],
        }),
        _ => None,
    }
}

/// External-deps allowlist for crates whose substrate is closed by
/// decision rather than direction. Today only `wyrd-format`: the
/// AGENTS.md hard rule names blake3, hex, thiserror, fastcdc, and serde
/// as the complete set.
fn format_external_allow() -> BTreeSet<&'static str> {
    ["blake3", "hex", "thiserror", "fastcdc", "serde"]
        .into_iter()
        .collect()
}

/// Check one member's production deps against its policy. Pure over the
/// edge sets so the negative tests below can prove the checker bites
/// without touching the filesystem.
fn check_member(member: &str, deps: &DepSet) -> Vec<String> {
    let Some(policy) = policy_for(member) else {
        return vec![format!(
            "workspace member `{member}` is not in the dependency-DAG policy: \
             add it deliberately in `layer_contracts.rs`, do not work around this test"
        )];
    };
    let allowed: BTreeSet<&str> = policy.workspace_allow.iter().copied().collect();
    let mut violations = Vec::new();
    for name in deps.keys() {
        if name == "wyrd-contracts" && member != "wyrd-contracts" {
            violations.push(format!(
                "`{member}` depends on `wyrd-contracts`: the suite is a leaf, \
                 nothing depends on it"
            ));
            continue;
        }
        if name.starts_with("wyrd-") {
            if !allowed.contains(name.as_str()) {
                violations.push(format!(
                    "`{member}` depends on `{name}`, outside its allowed set \
                     `{allowed:?}`: point the edge downward or amend the policy"
                ));
            }
            continue;
        }
        if policy.external_deny.contains(&name.as_str()) {
            violations.push(format!(
                "`{member}` gained forbidden dependency `{name}`: \
                 this crate must never grow it"
            ));
        }
        if member == "wyrd-format" && !format_external_allow().contains(name.as_str()) {
            violations.push(format!(
                "`wyrd-format` depends on `{name}`, outside the AGENTS.md substrate \
                 {{blake3, hex, thiserror, fastcdc, serde}}"
            ));
        }
    }
    violations
}

/// Collect production `[dependencies]` keys from a member manifest. Any
/// table named exactly `dependencies` counts (covers future
/// `[target.*.dependencies]`); `dev-dependencies` never does.
fn production_deps(manifest: &toml::Table) -> DepSet {
    let mut deps = DepSet::new();
    fn walk(table: &toml::Table, deps: &mut DepSet) {
        for (key, value) in table {
            if key == "dependencies" {
                if let Some(table) = value.as_table() {
                    deps.extend(table.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            } else if let Some(inner) = value.as_table() {
                walk(inner, deps);
            }
        }
    }
    walk(manifest, &mut deps);
    deps
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_manifest(dir: &Path) -> toml::Table {
    let text = fs::read_to_string(dir.join("Cargo.toml")).expect("member manifest is readable");
    text.parse().expect("member manifest parses as TOML")
}

/// `nostr*` use inside `wyrd-core` must stay within a single top-level
/// `src/` subsystem directory (the mailbox decision: control-plane
/// framing lives with sync control, never ambient across the node).
/// Manifests cannot express module scope, so this walks the sources.
fn check_core_nostr_scope(core_dir: &Path) -> Vec<String> {
    let mut holders: BTreeSet<String> = BTreeSet::new();
    fn walk(dir: &Path, root_src: &Path, holders: &mut BTreeSet<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root_src, holders);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = fs::read_to_string(&path).unwrap_or_default();
                let uses_nostr = text
                    .lines()
                    .any(|l| l.trim_start().starts_with("use nostr"));
                if uses_nostr {
                    let subsystem = path
                        .strip_prefix(root_src)
                        .ok()
                        .and_then(|rel| rel.components().next())
                        .map(|c| c.as_os_str().to_string_lossy().into_owned())
                        .unwrap_or_default();
                    holders.insert(format!("{subsystem} ({})", path.display()));
                }
            }
        }
    }
    let src = core_dir.join("src");
    walk(&src, &src, &mut holders);
    let subsystems: BTreeSet<&str> = holders
        .iter()
        .map(|h| h.split(' ').next().unwrap_or(""))
        .collect();
    if subsystems.len() > 1 {
        vec![format!(
            "`nostr*` use in `wyrd-core` spans subsystems {subsystems:?}: \
             keep it inside the mailbox subsystem (saw {holders:?})"
        )]
    } else {
        Vec::new()
    }
}

/// Contract 34: workspace dependency edges point downward along the
/// declared layering, and the policy fails closed on unknown crates.
#[test]
fn crate_dependencies_follow_the_layered_dag() {
    let root = workspace_root();
    let manifest = read_manifest(&root);
    let members: Vec<String> = manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .expect("workspace members list")
        .iter()
        .filter_map(|m| m.as_str().map(str::to_owned))
        .collect();
    // Never pass vacuously: an empty member list would check nothing.
    assert!(!members.is_empty(), "workspace declares no members");

    let mut violations = Vec::new();
    for member in &members {
        let name = member.rsplit('/').next().unwrap_or(member);
        let deps = production_deps(&read_manifest(&root.join(member)));
        violations.extend(check_member(name, &deps));
        if name == "wyrd-core" {
            violations.extend(check_core_nostr_scope(&root.join(member)));
        }
    }
    assert!(
        violations.is_empty(),
        "dependency-DAG violations:\n- {}",
        violations.join("\n- ")
    );
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    fn deps(names: &[&str]) -> DepSet {
        names
            .iter()
            .map(|n| (n.to_string(), toml::Value::Boolean(true)))
            .collect()
    }

    #[test]
    fn upward_edge_is_rejected() {
        let violations = check_member("wyrd-sync", &deps(&["wyrd-format", "wyrd-daemon"]));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-daemon"));
    }

    #[test]
    fn core_never_gains_presentation_deps() {
        for forbidden in ["fuser", "clap", "libc"] {
            let violations =
                check_member("wyrd-core", &deps(&["wyrd-format", "wyrd-sync", forbidden]));
            assert_eq!(violations.len(), 1, "for {forbidden}");
        }
    }

    #[test]
    fn cli_never_touches_the_view_crate() {
        let violations = check_member("wyrd-cli", &deps(&["wyrd-core", "wyrd-fuse"]));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-fuse"));
    }

    #[test]
    fn format_substrate_stays_closed() {
        let violations = check_member("wyrd-format", &deps(&["blake3", "tokio"]));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("tokio"));
    }

    #[test]
    fn unknown_member_fails_closed() {
        let violations = check_member("wyrd-something-new", &deps(&["wyrd-format"]));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("deliberately"));
    }

    #[test]
    fn contracts_is_a_leaf() {
        let violations = check_member("wyrd-daemon", &deps(&["wyrd-sync", "wyrd-contracts"]));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("leaf"));
    }

    #[test]
    fn production_deps_include_nested_tables_but_not_dev() {
        let manifest: toml::Table = r#"
            [dependencies]
            wyrd-format.workspace = true
            [dev-dependencies]
            wyrd-daemon.workspace = true
            [target.'cfg(unix)'.dependencies]
            libc = "0.2"
        "#
        .parse()
        .unwrap();
        let collected = production_deps(&manifest);
        assert!(collected.contains_key("wyrd-format"));
        assert!(collected.contains_key("libc"));
        assert!(!collected.contains_key("wyrd-daemon"));
    }
}
