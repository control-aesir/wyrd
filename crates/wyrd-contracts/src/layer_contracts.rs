//! The workspace dependency DAG is a load-bearing architectural invariant:
//! layers depend downward only (`wyrd-format → wyrd-sync → wyrd-core →
//! presentation`), so the Phase 1 extraction cannot smuggle a backward
//! edge while staying green. This module checks every member's
//! `[dependencies]` against the declared policy and fails closed on any
//! crate or edge the policy does not know: a new member, a new edge, or
//! a new external dependency is a deliberate policy edit, never an
//! accident.
//!
//! Only production `[dependencies]` are checked. `[dev-dependencies]`
//! stay exempt on purpose: they never ship, and test harnesses
//! legitimately reach further (in-process relays, fast-KDF profiles).
//!
//! Dependencies are resolved to effective package names before any rule
//! applies: a manifest alias (`transport = { package = "wyrd-daemon" }`)
//! is the same edge as the plain name, and a `workspace = true`
//! inheritance consults the workspace table for renames. The manifest
//! key is kept for diagnostics only.
//!
//! One rule needs source, not manifests, and lives here as well:
//! `nostr` use inside `wyrd-core` must stay inside one subsystem
//! directory (the mailbox decision), because manifests cannot scope a
//! dependency to a module. The scanner matches `use nostr`, bare
//! `nostr::` paths, and `extern crate nostr` as seen through a small
//! comment/string-stripping lexer (line and nestable block comments,
//! cooked, byte, and raw strings, char literals) — enough grammar for
//! a convention check, with the residual edge cases named at
//! `code_text`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

/// A normal `[dependencies]` edge set for one member: manifest key to
/// the raw value, so aliases resolve through the `package` field.
type DepSet = BTreeMap<String, toml::Value>;

/// Policy for one workspace member: the exact `wyrd-*` crates it may
/// depend on, and the exact third-party crates it may use. Anything
/// else fails closed.
struct MemberPolicy {
    workspace_allow: &'static [&'static str],
    external_allow: &'static [&'static str],
}

fn policy_for(member: &str) -> Option<MemberPolicy> {
    match member {
        // Hard rule from AGENTS.md: plaintext world, closed substrate.
        "wyrd-format" => Some(MemberPolicy {
            workspace_allow: &[],
            external_allow: &["blake3", "hex", "thiserror", "fastcdc", "serde"],
        }),
        // Protocol machinery: format below, a pinned third-party set,
        // nothing upward or sideways. `tracing` is the structured
        // forensics facade (per-pass sync counts, intake verdicts,
        // outbox sends) — events only, no subscriber, no I/O.
        "wyrd-sync" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format"],
            external_allow: &[
                "iroh",
                "iroh-blobs",
                "iroh-gossip",
                "bao-tree",
                "bytes",
                "n0-future",
                "nostr",
                "secp256k1",
                "chacha20poly1305",
                "hkdf",
                "sha2",
                "argon2",
                "getrandom",
                "blake3",
                "tokio",
                "thiserror",
                "tracing",
                "zeroize",
            ],
        }),
        // The embeddable node: sync and format below; the mailbox
        // subsystem's async and control-plane crates; never presentation
        // (fuser), argument parsing (clap), POSIX errno mapping (libc),
        // or process-signal handling. The `wyrd-core` edge on `wyrd-fuse`
        // is allowed now so Phase 2 can point the adapter at the
        // provider-neutral API without a policy edit. `tracing` is the
        // structured forensics facade (per-pass sync counts) — events
        // only, no subscriber, no I/O.
        "wyrd-core" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync"],
            external_allow: &[
                "futures-util",
                "getrandom",
                "nostr",
                "nostr-sdk",
                "thiserror",
                "tokio",
                "tracing",
            ],
        }),
        "wyrd-fuse" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-core"],
            external_allow: &["thiserror"],
        }),
        // The composer and process host: everything below, never the CLI
        // (presentation depends on the host's public surface, not the
        // reverse) and never the contract suite.
        "wyrd-daemon" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync", "wyrd-fuse", "wyrd-core"],
            external_allow: &[
                "fuser",
                "futures-util",
                "getrandom",
                "hex",
                "libc",
                "clap",
                "nostr",
                "nostr-connect",
                "nostr-sdk",
                "thiserror",
                "tokio",
                "tracing",
                "tracing-subscriber",
                "tracing-log",
                "zeroize",
            ],
        }),
        // The `wyrd` process host: argument parsing, credential
        // files, mount orchestration, diagnostics, and exit codes over
        // the daemon's public surface. It mounts through the FUSE
        // adapter, so the host crates (fuser, libc, tracing) and the
        // credential/control-plane crates (hex, nostr) are its own —
        // never the sync transport internals or the contract suite.
        "wyrd-cli" => Some(MemberPolicy {
            workspace_allow: &["wyrd-format", "wyrd-sync", "wyrd-core", "wyrd-daemon"],
            external_allow: &[
                "clap",
                "fuser",
                "hex",
                "libc",
                "nostr",
                "thiserror",
                "tracing",
                "tracing-subscriber",
                "tracing-log",
                "zeroize",
            ],
        }),
        // The suite itself: leaf, depends on every crate, and the
        // reverse edge is checked separately below. No third-party
        // production deps today; any is a deliberate edit.
        "wyrd-contracts" => Some(MemberPolicy {
            workspace_allow: &[
                "wyrd-format",
                "wyrd-sync",
                "wyrd-fuse",
                "wyrd-core",
                "wyrd-daemon",
                "wyrd-cli",
            ],
            external_allow: &[],
        }),
        _ => None,
    }
}

/// Effective package name for one manifest entry: the `package` rename
/// wins; a `workspace = true` inheritance consults the workspace table
/// for the rename; otherwise the key is the name.
fn effective_name(key: &str, value: &toml::Value, workspace_deps: &toml::Table) -> String {
    if let Some(table) = value.as_table() {
        if let Some(package) = table.get("package").and_then(|p| p.as_str()) {
            return package.to_owned();
        }
        if table.get("workspace").and_then(|w| w.as_bool()) == Some(true) {
            if let Some(renamed) = workspace_deps
                .get(key)
                .and_then(|w| w.as_table())
                .and_then(|w| w.get("package"))
                .and_then(|p| p.as_str())
            {
                return renamed.to_owned();
            }
        }
    }
    key.to_owned()
}

/// Check one member's production deps against its policy. Pure over the
/// edge sets so the negative tests below can prove the checker bites
/// without touching the filesystem.
fn check_member(member: &str, deps: &DepSet, workspace_deps: &toml::Table) -> Vec<String> {
    let Some(policy) = policy_for(member) else {
        return vec![format!(
            "workspace member `{member}` is not in the dependency-DAG policy: \
             add it deliberately in `layer_contracts.rs`, do not work around this test"
        )];
    };
    let workspace_allowed: BTreeSet<&str> = policy.workspace_allow.iter().copied().collect();
    let external_allowed: BTreeSet<&str> = policy.external_allow.iter().copied().collect();
    let mut violations = Vec::new();
    for (key, value) in deps {
        let name = effective_name(key, value, workspace_deps);
        if name == "wyrd-contracts" && member != "wyrd-contracts" {
            violations.push(format!(
                "`{member}` depends on `wyrd-contracts` (as `{key}`): the suite is a \
                 leaf, nothing depends on it"
            ));
            continue;
        }
        if name.starts_with("wyrd-") {
            if !workspace_allowed.contains(name.as_str()) {
                violations.push(format!(
                    "`{member}` depends on `{name}` (as `{key}`), outside its allowed set \
                     `{workspace_allowed:?}`: point the edge downward or amend the policy"
                ));
            }
            continue;
        }
        if !external_allowed.contains(name.as_str()) {
            violations.push(format!(
                "`{member}` depends on `{name}` (as `{key}`), outside its allowed \
                 third-party set `{external_allowed:?}`: amend the policy deliberately \
                 or drop the edge"
            ));
        }
    }
    violations
}

/// Collect production `[dependencies]` entries from a member manifest.
/// Any table named exactly `dependencies` counts (covers future
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

fn workspace_dep_table(root_manifest: &toml::Table) -> toml::Table {
    root_manifest
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
        .cloned()
        .unwrap_or_default()
}

/// Strip comments and string/char literals from whole file text,
/// preserving newlines so per-line matching below stays meaningful.
/// Handles `//` anywhere outside literals, nestable `/* */` block
/// comments, `"..."` with escapes, `b"..."`, raw `r"..."`/`r#"..."#`
/// forms, and `'x'` char literals (a `'` skips to its line's closing
/// quote; lifetimes without one pass through untouched). A small lexer
/// for a convention check, not a grammar: pathological nesting of
/// quotes inside lifetimes is out of scope.
fn code_text(text: &str) -> String {
    let mut code = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Line comment: `//` in normal state runs to (not past) `\n`.
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                code.push(' ');
                i += 1;
            }
            continue;
        }
        // Block comment, nestable per the Rust grammar.
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 0;
            while i < chars.len() {
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 1;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 1;
                    if depth == 0 {
                        i += 1;
                        break;
                    }
                }
                if chars[i] == '\n' {
                    code.push('\n');
                } else {
                    code.push(' ');
                }
                i += 1;
            }
            continue;
        }
        // Raw string: `r"..."`, `r#"..."#`, ... (and `br` variants).
        if (c == 'r' || (c == 'b' && chars.get(i + 1) == Some(&'r'))) && {
            let mut j = if c == 'b' { i + 1 } else { i };
            j += 1;
            while chars.get(j) == Some(&'#') {
                j += 1;
            }
            chars.get(j) == Some(&'"')
        } {
            let mut hashes = 0;
            let mut j = if c == 'b' { i + 2 } else { i + 1 };
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            j += 1; // opening quote
            loop {
                if j >= chars.len() {
                    i = j;
                    break;
                }
                if chars[j] == '"' {
                    let mut k = j + 1;
                    let mut seen = 0;
                    while seen < hashes && chars.get(k) == Some(&'#') {
                        seen += 1;
                        k += 1;
                    }
                    if seen == hashes {
                        j = k;
                        i = j;
                        break;
                    }
                }
                if chars[j] == '\n' {
                    code.push('\n');
                }
                j += 1;
            }
            continue;
        }
        // Ordinary or byte string.
        if c == '"' || (c == 'b' && chars.get(i + 1) == Some(&'"')) {
            i += if c == 'b' { 2 } else { 1 };
            while i < chars.len() && chars[i] != '"' && chars[i] != '\n' {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += usize::from(i < chars.len() && chars[i] == '"');
            continue;
        }
        // Char literal: skip to the line's closing quote when there is
        // one; otherwise this is a lifetime tick, pass it through.
        if c == '\'' {
            let rest: String = chars[i + 1..].iter().collect();
            let closes = rest.find('\'').is_some_and(|p| !rest[..p].contains('\n'));
            if closes {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            code.push(c);
            i += 1;
            continue;
        }
        code.push(c);
        i += 1;
    }
    code
}

/// Does one stripped source line use a `nostr*` crate.
fn line_uses_nostr(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("use nostr")
        || trimmed.starts_with("extern crate nostr")
        || line.contains("nostr::")
}

/// Subsystem directories (top-level `src/` children) holding `nostr*`
/// use, from an explicit file list. Pure so tests can pin the scanner
/// without touching the filesystem.
fn nostr_holding_subsystems(files: &[(&str, &str)]) -> BTreeSet<String> {
    files
        .iter()
        .filter(|(_, text)| code_text(text).lines().any(line_uses_nostr))
        .filter_map(|(path, _)| {
            Path::new(path)
                .components()
                .nth(1)
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
        })
        .collect()
}

/// `nostr*` use inside `wyrd-core` must stay within a single top-level
/// `src/` subsystem directory (the mailbox decision: control-plane
/// framing lives with sync control, never ambient across the node).
/// The walk fails closed: unreadable directories and files are
/// violations naming the path (never silent skips), and a walk that
/// examines no `.rs` files at all fails too — an empty file set
/// proves nothing, so "no `nostr*` references" and "nothing examined"
/// are different verdicts.
fn check_core_nostr_scope(core_dir: &Path) -> Vec<String> {
    let mut files: Vec<(String, String)> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut examined = 0usize;
    fn walk(
        dir: &Path,
        src: &Path,
        files: &mut Vec<(String, String)>,
        errors: &mut Vec<String>,
        examined: &mut usize,
    ) {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                errors.push(format!("cannot read directory `{}`: {err}", dir.display()));
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    errors.push(format!("cannot list entry in `{}`: {err}", dir.display()));
                    continue;
                }
            };
            let path = entry.path();
            if path.is_dir() {
                walk(&path, src, files, errors, examined);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(src)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                // Prefix with `src/` so the subsystem is always at
                // component index 1, matching the test convention.
                match fs::read_to_string(&path) {
                    Ok(text) => {
                        *examined += 1;
                        files.push((format!("src/{rel}"), text));
                    }
                    Err(err) => {
                        errors.push(format!("cannot read file `{}`: {err}", path.display()));
                    }
                }
            }
        }
    }
    let src = core_dir.join("src");
    walk(&src, &src, &mut files, &mut errors, &mut examined);
    if !errors.is_empty() {
        return errors;
    }
    if examined == 0 {
        return vec![format!(
            "`nostr*` scope check examined no `.rs` files under `{}`: \
             an empty walk proves nothing, failing closed",
            src.display()
        )];
    }
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, t)| (p.as_str(), t.as_str()))
        .collect();
    let subsystems = nostr_holding_subsystems(&refs);
    if subsystems.len() > 1 {
        vec![format!(
            "`nostr*` use in `wyrd-core` spans subsystems {subsystems:?}: \
             keep it inside the mailbox subsystem"
        )]
    } else {
        Vec::new()
    }
}

/// Contract 34 (packaging half): the distribution build compiles the
/// user-facing binary from `wyrd-cli`. The Phase 4 move broke this
/// once (the flake built `-p wyrd-daemon`, which installs no binary,
/// and `wyrd-dist` failed packing `bin/wyrd`), so it is asserted, not
/// remembered. A structural guard over the flake text — not a
/// substitute for a release `nix build` — so it matches every
/// `cargoExtraArgs` line rather than trusting line layout, and fails
/// closed if the flag ever names another package.
#[test]
fn flake_builds_the_binary_from_wyrd_cli() {
    let text =
        fs::read_to_string(workspace_root().join("flake.nix")).expect("flake.nix is readable");
    let args: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("cargoExtraArgs"))
        .collect();
    assert!(
        !args.is_empty(),
        "flake names no binary source package at all"
    );
    assert!(
        args.iter().any(|line| line.contains("-p wyrd-cli")),
        "distribution must build the binary from wyrd-cli, found: {args:?}"
    );
    assert!(
        !args.iter().any(|line| line.contains("-p wyrd-daemon")),
        "distribution must not build the binary from the library-only daemon: {args:?}"
    );
}

/// Contract 34 (membership half): the workspace member set is exact.
/// Additions fail closed through the unknown-member policy; removals
/// would silently narrow every member-wide check, so the set itself
/// is pinned. Order is not an invariant (Cargo ignores it), so the
/// comparison is order-insensitive and a reorder never fails this.
#[test]
fn workspace_members_are_exact() {
    let root_manifest = read_manifest(&workspace_root());
    let mut members: Vec<String> = root_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .expect("workspace members list")
        .iter()
        .filter_map(|m| m.as_str().map(str::to_owned))
        .collect();
    members.sort();
    let mut expected = [
        "crates/wyrd-format",
        "crates/wyrd-sync",
        "crates/wyrd-fuse",
        "crates/wyrd-core",
        "crates/wyrd-daemon",
        "crates/wyrd-cli",
        "crates/wyrd-contracts",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        members, expected,
        "workspace membership drifted: add or remove the member deliberately here"
    );
}

/// Contract 34: workspace dependency edges point downward along the
/// declared layering, and the policy fails closed on unknown crates,
/// edges, and third-party additions. The `wyrd-core`/`wyrd-cli`
/// clauses activate when those crates join the workspace.
#[test]
fn crate_dependencies_follow_the_layered_dag() {
    let root = workspace_root();
    let root_manifest = read_manifest(&root);
    let members: Vec<String> = root_manifest
        .get("workspace")
        .and_then(|w| w.get("members"))
        .and_then(|m| m.as_array())
        .expect("workspace members list")
        .iter()
        .filter_map(|m| m.as_str().map(str::to_owned))
        .collect();
    // Never pass vacuously: an empty member list would check nothing.
    assert!(!members.is_empty(), "workspace declares no members");
    let workspace_deps = workspace_dep_table(&root_manifest);

    let mut violations = Vec::new();
    for member in &members {
        let name = member.rsplit('/').next().unwrap_or(member);
        let deps = production_deps(&read_manifest(&root.join(member)));
        violations.extend(check_member(name, &deps, &workspace_deps));
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
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Scratch `wyrd-core`-shaped root (`<root>/src/`) under the temp
    /// dir. The caller owns cleanup; tests remove the tree before
    /// asserting so a failure never leaks a permission-stripped dir.
    fn scratch_core_dir() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "wyrd-nostr-scope-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("src")).expect("scratch src dir is creatable");
        root
    }

    fn empty_ws() -> toml::Table {
        toml::Table::new()
    }

    fn deps(names: &[&str]) -> DepSet {
        names
            .iter()
            .map(|n| (n.to_string(), toml::Value::Boolean(true)))
            .collect()
    }

    fn manifest_deps(manifest: &str) -> DepSet {
        production_deps(&manifest.parse().unwrap())
    }

    #[test]
    fn upward_edge_is_rejected() {
        let violations = check_member(
            "wyrd-sync",
            &deps(&["wyrd-format", "wyrd-daemon"]),
            &empty_ws(),
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-daemon"));
    }

    #[test]
    fn aliased_upward_edge_is_rejected_through_manifest_path() {
        let parsed = manifest_deps(
            r#"
            [dependencies]
            wyrd-format.workspace = true
            transport = { package = "wyrd-daemon", path = "../wyrd-daemon" }
        "#,
        );
        let violations = check_member("wyrd-sync", &parsed, &empty_ws());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-daemon"));
        assert!(violations[0].contains("transport"));
    }

    #[test]
    fn workspace_inherited_rename_resolves() {
        let root: toml::Table = r#"
            [workspace.dependencies]
            renamed = { package = "wyrd-daemon" }
        "#
        .parse()
        .unwrap();
        let parsed = manifest_deps(
            r#"
            [dependencies]
            renamed.workspace = true
        "#,
        );
        let violations = check_member("wyrd-sync", &parsed, &workspace_dep_table(&root));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-daemon"));
    }

    #[test]
    fn core_never_gains_presentation_deps() {
        for forbidden in ["fuser", "clap", "libc"] {
            let violations = check_member(
                "wyrd-core",
                &deps(&["wyrd-format", "wyrd-sync", forbidden]),
                &empty_ws(),
            );
            assert_eq!(violations.len(), 1, "for {forbidden}");
        }
    }

    #[test]
    fn aliased_forbidden_external_is_rejected() {
        let parsed = manifest_deps(
            r#"
            [dependencies]
            wyrd-sync.workspace = true
            fuse_bindings = { package = "fuser", version = "0.18" }
        "#,
        );
        let violations = check_member("wyrd-core", &parsed, &empty_ws());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("fuser"));
    }

    #[test]
    fn new_external_dep_fails_closed() {
        let violations = check_member(
            "wyrd-sync",
            &deps(&["wyrd-format", "some-new-crate"]),
            &empty_ws(),
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("some-new-crate"));
    }

    #[test]
    fn cli_never_touches_the_view_crate() {
        let violations = check_member("wyrd-cli", &deps(&["wyrd-core", "wyrd-fuse"]), &empty_ws());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("wyrd-fuse"));
    }

    #[test]
    fn cli_host_deps_are_exact() {
        // The process host's full production edge set, pinned so a
        // widening (or a silent policy trim) fails here and not in
        // review vigilance. The live contract above checks the real
        // manifest; this names the expectation.
        let violations = check_member(
            "wyrd-cli",
            &deps(&[
                "wyrd-format",
                "wyrd-sync",
                "wyrd-core",
                "wyrd-daemon",
                "clap",
                "fuser",
                "hex",
                "libc",
                "nostr",
                "thiserror",
                "tracing",
                "tracing-subscriber",
                "tracing-log",
                "zeroize",
            ]),
            &empty_ws(),
        );
        assert!(
            violations.is_empty(),
            "cli allowlist drifted: {violations:?}"
        );
    }

    #[test]
    fn format_substrate_stays_closed() {
        let violations = check_member("wyrd-format", &deps(&["blake3", "tokio"]), &empty_ws());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("tokio"));
    }

    #[test]
    fn unknown_member_fails_closed() {
        let violations = check_member("wyrd-something-new", &deps(&["wyrd-format"]), &empty_ws());
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("deliberately"));
    }

    #[test]
    fn contracts_is_a_leaf() {
        let violations = check_member(
            "wyrd-daemon",
            &deps(&["wyrd-sync", "wyrd-contracts"]),
            &empty_ws(),
        );
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("leaf"));
    }

    #[test]
    fn production_deps_include_nested_tables_but_not_dev() {
        let collected = manifest_deps(
            r#"
            [dependencies]
            wyrd-format.workspace = true
            [dev-dependencies]
            wyrd-daemon.workspace = true
            [target.'cfg(unix)'.dependencies]
            libc = "0.2"
        "#,
        );
        assert!(collected.contains_key("wyrd-format"));
        assert!(collected.contains_key("libc"));
        assert!(!collected.contains_key("wyrd-daemon"));
    }

    #[test]
    fn nostr_scope_pins_to_one_subsystem() {
        let single = [
            ("src/mailbox/mod.rs", "use nostr_sdk::prelude::Client;"),
            (
                "src/mailbox/seen_store.rs",
                "let id = nostr::event::EventId::new();",
            ),
            ("src/session.rs", "use std::collections::BTreeMap;"),
        ];
        assert_eq!(
            nostr_holding_subsystems(&single),
            BTreeSet::from(["mailbox".to_owned()])
        );

        let spread = [
            ("src/mailbox/mod.rs", "use nostr_sdk::prelude::Client;"),
            ("src/session/mod.rs", "extern crate nostr;"),
        ];
        assert_eq!(
            nostr_holding_subsystems(&spread),
            BTreeSet::from(["mailbox".to_owned(), "session".to_owned()])
        );
    }

    #[test]
    fn nostr_scope_ignores_comments_and_urls() {
        let files = [
            ("src/session/mod.rs", "// see nostr:: docs for the framing"),
            (
                "src/session/mod.rs",
                "let x = 1;// attached nostr:: comment",
            ),
            (
                "src/session/mod.rs",
                "/* block nostr:: mention\nspanning lines, /* nested */ done */",
            ),
            ("src/node/mod.rs", "let url = \"http://relay/nostr::x\";"),
            ("src/node/mod.rs", "let raw = r#\"nostr:: in raw\"#;"),
            ("src/node/mod.rs", "let tick = &'static str;"),
            ("src/node/mod.rs", "use std::io;"),
        ];
        assert!(nostr_holding_subsystems(&files).is_empty());
    }

    #[test]
    fn nostr_scope_still_detects_real_use_beside_noise() {
        let files = [
            (
                "src/mailbox/mod.rs",
                "/* nostr:: in a comment */\nuse nostr_sdk::prelude::Client;",
            ),
            (
                "src/mailbox/seen_store.rs",
                "let doc = \"nostr:: in a string\";\nlet id = nostr::event::EventId::new();",
            ),
        ];
        assert_eq!(
            nostr_holding_subsystems(&files),
            BTreeSet::from(["mailbox".to_owned()])
        );
    }

    #[test]
    fn nostr_scope_fails_when_source_tree_is_missing() {
        let missing =
            std::env::temp_dir().join(format!("wyrd-nostr-scope-missing-{}", std::process::id()));
        // A crashed earlier run must not leave the tree behind and
        // flip this to the empty-dir case.
        let _ = fs::remove_dir_all(&missing);
        let violations = check_core_nostr_scope(&missing);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains(&*missing.join("src").to_string_lossy()),
            "failure must name the unreadable tree: {violations:?}"
        );
    }

    #[test]
    fn nostr_scope_fails_when_no_files_are_examined() {
        let root = scratch_core_dir();
        let violations = check_core_nostr_scope(&root);
        fs::remove_dir_all(&root).expect("scratch cleanup");
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("no `.rs` files"),
            "an empty walk must fail closed: {violations:?}"
        );
    }

    /// Permission-stripping proves the nested-dir branch on ordinary
    /// runners; on elevated runners (root reads through `0o000`) the
    /// same test asserts the complementary truth instead — a fully
    /// readable fixture passes clean — so it is an assertion everywhere.
    #[cfg(unix)]
    #[test]
    fn nostr_scope_surfaces_an_unreadable_nested_dir() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch_core_dir();
        let mailbox = root.join("src").join("mailbox");
        fs::create_dir_all(&mailbox).expect("scratch mailbox dir");
        fs::write(mailbox.join("mod.rs"), "use nostr_sdk::prelude::Client;").expect("scratch file");
        let opaque = root.join("src").join("opaque");
        fs::create_dir_all(&opaque).expect("scratch opaque dir");
        fs::set_permissions(&opaque, fs::Permissions::from_mode(0o000)).expect("strip permissions");
        // No root-proof way to fail `read_dir` from the filesystem
        // exists, so an elevated runner reads through `0o000`. Rather
        // than print-and-return (nextest hides passing-test output, so
        // a note proves nothing), assert the complementary truth on
        // that path: everything is readable, so the fixture tree must
        // yield a clean scope verdict. That keeps the test an assertion
        // on every runner and doubles as happy-path coverage of the
        // fixture itself.
        if fs::read_dir(&opaque).is_ok() {
            let violations = check_core_nostr_scope(&root);
            fs::remove_dir_all(&root).expect("scratch cleanup");
            assert!(
                violations.is_empty(),
                "fully readable fixture must pass clean: {violations:?}"
            );
            return;
        }
        let violations = check_core_nostr_scope(&root);
        fs::set_permissions(&opaque, fs::Permissions::from_mode(0o755)).expect("restore");
        fs::remove_dir_all(&root).expect("scratch cleanup");
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("opaque"),
            "nested read failure must surface: {violations:?}"
        );
    }

    /// A dangling symlink fails `read_to_string` on every runner,
    /// including elevated ones that read through `0o000`, so the
    /// unreadable-file proof is runner-independent. `is_dir` follows
    /// links (false for a dangling link) and the `rs` extension still
    /// selects it, landing in exactly the file-error branch.
    #[cfg(unix)]
    #[test]
    fn nostr_scope_surfaces_an_unreadable_file() {
        let root = scratch_core_dir();
        let mailbox = root.join("src").join("mailbox");
        fs::create_dir_all(&mailbox).expect("scratch dirs");
        let file = mailbox.join("mod.rs");
        std::os::unix::fs::symlink("nowhere.rs", &file).expect("dangling symlink");
        assert!(
            fs::read_to_string(&file).is_err(),
            "the dangling link must stay unreadable"
        );
        let violations = check_core_nostr_scope(&root);
        fs::remove_dir_all(&root).expect("scratch cleanup");
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("mod.rs"),
            "unreadable file must surface: {violations:?}"
        );
    }
}
