//! Help-surface contract: every `--help` page plus the error paths,
//! hashed under a fixed environment.
//!
//! Run: `cargo test -p wyrd-cli --test help_contract` (part of the
//! normal `cargo test -p wyrd-cli` gate). After an intentional surface
//! change, re-record with `HELP_CONTRACT_RECORD=1` (subject to review)
//! and commit the updated `help-contract.blake3` beside this file.
//!
//! The fixed environment (`CLICOLOR=0 NO_COLOR=1 TERM=dumb
//! COLUMNS=100`) keeps terminal width, color, and paging out of the
//! contract. Page contents embed the argv and exit code but never the
//! binary path, so the same hash file holds on any machine.
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

const FIXED_ENV: [(&str, &str); 4] = [
    ("CLICOLOR", "0"),
    ("NO_COLOR", "1"),
    ("TERM", "dumb"),
    ("COLUMNS", "100"),
];
const EXPECTED_FILE: &str = "help-contract.blake3";

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_wyrd"))
        .args(args)
        .envs(FIXED_ENV)
        .output()
        .expect("wyrd binary must run");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8(output.stdout).expect("help is UTF-8"),
        String::from_utf8(output.stderr).expect("help is UTF-8"),
    )
}

fn subcommands(help: &str) -> Vec<String> {
    let mut cmds = Vec::new();
    let mut in_section = false;
    for line in help.lines() {
        if line.trim() == "Commands:" {
            in_section = true;
            continue;
        }
        if in_section {
            if line.starts_with("  ") && !line.trim().is_empty() {
                let name = line.split_whitespace().next().unwrap_or("");
                if name != "help" && !name.is_empty() {
                    cmds.push(name.to_string());
                }
            } else if line.starts_with("Options:") {
                break;
            } else if line.trim().is_empty() || line.starts_with("Arguments:") {
                // End of the Commands block: anything indented past
                // here is a positional argument (e.g. `<DRIVE_DIR>`),
                // not a subcommand.
                break;
            } else {
                break;
            }
        }
    }
    cmds
}

fn slug(key: &[String]) -> String {
    if key.is_empty() {
        "root".to_string()
    } else {
        key.join("_")
    }
}

fn capture() -> BTreeMap<String, String> {
    let mut pages = BTreeMap::new();

    fn visit(pages: &mut BTreeMap<String, String>, args: Vec<String>, depth: usize) {
        // Deepest real page today is `snapshot recover run` at depth
        // 3; raise this cap if the command tree ever nests deeper.
        if pages.contains_key(&slug(&args)) || depth > 3 {
            return;
        }
        let mut full = args.clone();
        full.push("--help".to_string());
        let refs: Vec<&str> = full.iter().map(String::as_str).collect();
        let (rc, out, err) = run(&refs);
        let key = slug(&args);
        pages.insert(
            key,
            format!(
                "$ wyrd {}\nrc={rc}\n--- stdout ---\n{out}--- stderr ---\n{err}",
                full.join(" ")
            ),
        );
        if rc == 0 {
            for sub in subcommands(&out) {
                let mut next = args.clone();
                next.push(sub);
                visit(pages, next, depth + 1);
            }
        }
    }

    visit(&mut pages, Vec::new(), 0);
    for (name, args) in [
        ("error_no_args", [].as_slice()),
        ("error_bogus_command", ["bogus-command"].as_slice()),
        ("error_bogus_nested", ["member", "bogus-action"].as_slice()),
        ("error_bad_flag", ["--bogus-flag"].as_slice()),
    ] {
        let (rc, out, err) = run(args);
        pages.insert(
            name.to_string(),
            format!(
                "$ wyrd {}\nrc={rc}\n--- stdout ---\n{out}--- stderr ---\n{err}",
                args.join(" ")
            ),
        );
    }
    pages
}

#[test]
fn help_surface_is_byte_identical() {
    let pages = capture();
    let mut lines = Vec::new();
    for (page_slug, body) in &pages {
        lines.push(format!(
            "{}  {page_slug}",
            blake3::hash(body.as_bytes()).to_hex()
        ));
    }
    lines.sort();
    let sha_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(EXPECTED_FILE);
    if std::env::var("HELP_CONTRACT_RECORD").is_ok() {
        std::fs::write(&sha_path, lines.join("\n") + "\n").unwrap();
        println!("recorded {} pages to {}", lines.len(), sha_path.display());
        return;
    }
    let expected = std::fs::read_to_string(&sha_path).expect("help-contract.blake3 must exist");
    let expected: Vec<&str> = expected.lines().collect();
    let actual: Vec<&str> = lines.iter().map(String::as_str).collect();
    for (page_slug, body) in &pages {
        let digest = blake3::hash(body.as_bytes()).to_hex().to_string();
        if !expected.iter().any(|l| l.starts_with(&digest)) {
            println!("CHANGED page {page_slug}:\n{body}");
        }
    }
    assert_eq!(
        actual, expected,
        "help surface changed; re-record only for an intentional change"
    );
}
