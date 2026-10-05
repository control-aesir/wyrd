//! End-to-end policy commands: init, author, pin/unpin/evict,
//! cache status/policy through the real `command` entrypoint,
//! proving the wiring the core and daemon tests prove the semantics
//! of. Policy assertions reopen the engine from custody, the way a
//! second CLI invocation would.

use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_format::{Entry, ObjectKind, ObjectStore, Tree};

/// A drive with two authored files, plus the credential flags every
/// policy command needs.
fn authored_drive() -> (TempDir, Vec<String>) {
    let temp = TempDir::new();
    let identity_file = temp.0.join("identity");
    let passphrase_file = temp.0.join("passphrase");
    let drive = temp.0.join("drive");
    write_secret(&identity_file, [0x11; 32]);
    write_secret(&passphrase_file, b"test-pass\n");
    let creds = vec![
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ];
    command(vec![
        "init".into(),
        drive.display().to_string(),
        "--identity-file".into(),
        identity_file.display().to_string(),
        "--passphrase-file".into(),
        passphrase_file.display().to_string(),
    ])
    .unwrap();
    let identity = read_identity(&identity_file).unwrap();
    let mut engine = Engine::open_keystore(drive.clone(), "test-pass", identity).unwrap();
    let mut store = FsObjectStore::open(drive.clone()).unwrap();
    let a = store.insert(ObjectKind::Chunk, b"alpha bytes").unwrap();
    let b = store.insert(ObjectKind::Chunk, b"beta bytes").unwrap();
    let root = Tree::from_entries(vec![
        Entry::file("a.txt", 11, false, vec![a]).unwrap(),
        Entry::file("b.txt", 10, false, vec![b]).unwrap(),
    ])
    .unwrap()
    .insert_into(&mut store)
    .unwrap();
    engine.author_snapshot(&store, root).unwrap();
    (temp, creds)
}

fn drive_of(temp: &TempDir) -> String {
    temp.0.join("drive").display().to_string()
}

#[test]
fn pin_status_and_policy_roundtrip() {
    let (temp, creds) = authored_drive();
    let drive = drive_of(&temp);
    let mut pin = vec!["pin".into(), drive.clone(), "a.txt".into()];
    pin.extend(creds.clone());
    command(pin).unwrap();
    // A second invocation observes the durable promise. The
    // flattened credentials precede the nested subcommand; clap
    // parses positionally past it.
    let mut status = vec!["cache".into(), drive.clone()];
    status.extend(creds.clone());
    status.extend(["status".into(), "a.txt".into()]);
    command(status).unwrap();
    let mut policy = vec!["cache".into(), drive.clone()];
    policy.extend(creds.clone());
    policy.push("policy".into());
    command(policy).unwrap();
    drop(temp);
}

/// `cache policy` measures a real drive end to end: the object-store
/// walk, the fact-log walk, and the vault walk all run against the
/// authored drive without error. The rendered numbers are asserted in
/// `policy_renderers_name_counts_and_quadrants`; this pins the wiring
/// the renderers ride.
#[test]
fn policy_measures_a_real_drive() {
    let (temp, creds) = authored_drive();
    let drive = drive_of(&temp);
    let mut policy = vec!["cache".into(), drive.clone()];
    policy.extend(creds);
    policy.push("policy".into());
    command(policy).unwrap();
    drop(temp);
}

#[test]
fn evict_refuses_pins_until_unpinned() {
    let (temp, creds) = authored_drive();
    let drive = drive_of(&temp);
    let mut pin = vec!["pin".into(), drive.clone(), "a.txt".into()];
    pin.extend(creds.clone());
    command(pin).unwrap();
    // Same-path evict refuses while pinned.
    let mut evict = vec!["evict".into(), drive.clone(), "a.txt".into()];
    evict.extend(creds.clone());
    let error = command(evict).unwrap_err();
    assert!(
        matches!(error, CliError::Policy(_)),
        "evict must refuse pinned content, got {error:?}"
    );
    let mut unpin = vec!["unpin".into(), drive.clone(), "a.txt".into()];
    unpin.extend(creds.clone());
    command(unpin).unwrap();
    let mut evict = vec!["evict".into(), drive.clone(), "a.txt".into()];
    evict.extend(creds);
    command(evict).unwrap();
    drop(temp);
}

#[test]
fn pin_missing_path_names_the_failure() {
    let (temp, creds) = authored_drive();
    let drive = drive_of(&temp);
    let mut pin = vec!["pin".into(), drive.clone(), "nope.txt".into()];
    pin.extend(creds);
    let error = command(pin).unwrap_err();
    assert!(
        matches!(error, CliError::Policy(_)),
        "missing paths fail as policy errors, got {error:?}"
    );
    drop(temp);
}

#[test]
fn policy_renderers_name_counts_and_quadrants() {
    let report = wyrd_core::policy::PinReport {
        files: 2,
        dirs: 1,
        symlinks_skipped: 1,
        pinned: 3,
        already_pinned: 1,
    };
    let rendered = pin_render("docs", &report);
    assert!(rendered.contains("pinned 3 objects (1 already pinned)"));
    assert!(rendered.contains("2 files"));
    assert!(rendered.contains("1 symlinks skipped"));
    let census = ResidencyCensus {
        files: vec![wyrd_core::policy::FileResidency {
            path: "a.txt".into(),
            chunks: Vec::new(),
            pinned_chunks: Vec::new(),
            policy: RetentionPolicy::Pinned,
            local: LocalPresence::Present,
        }],
        conflicts: vec!["split".into()],
        dirs: 0,
        symlinks_skipped: 0,
    };
    let rendered = cache_status_render("docs", &census);
    assert!(rendered.contains("PINNED"));
    assert!(rendered.contains("PRESENT"));
    assert!(rendered.contains("a.txt"));
    assert!(rendered.contains("CONFLICT"));
    assert!(rendered.contains("split"));
    let accounting = RetentionAccounting {
        retained_content: 812,
        fact_log: 37,
        sync_vault: 124,
        quota: None,
    };
    let budgets = LiveConfig::for_local_sync().budgets;
    let rendered = cache_policy_render(&census, &accounting, &budgets);
    assert!(rendered.contains("pinned files: 1"));
    assert!(rendered.contains("retained_bytes_quota: unlimited"));
    // OD-26-B option B: the report names each dimension and labels
    // whether it backs enforcement or merely observes. A single total
    // known to be low is not acceptable output.
    assert!(rendered.contains("retained content: 812 (quota-enforced)"));
    assert!(rendered.contains("fact log: 37 (observational)"));
    assert!(rendered.contains("sync vault: 124 (observational)"));
    assert!(rendered.contains("total accounted: 973 (observational)"));
    // OD-26-A option C: with no configured ceiling the report advises
    // one, explicitly non-authoritative — never a silent default.
    assert!(rendered.contains("advisory ceiling (non-authoritative)"));
    assert!(
        rendered.contains("conflicts: 1 skipped (never walked):\n  split"),
        "policy totals name the subtrees they never walked"
    );
}
