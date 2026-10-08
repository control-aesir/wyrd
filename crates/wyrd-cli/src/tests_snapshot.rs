//! Snapshot-list/heads/merge CLI edges: argument validation fails
//! at the boundary, engine verdicts pass through, and the reports
//! render the `@N` merge numbers.

use super::tests_harness::{write_secret, TempDir};
use super::*;
use wyrd_format::{Entry, FsObjectStore, ObjectKind, ObjectStore, SnapshotId, Tree};
use wyrd_sync::runtime::EngineError;

struct Fixture {
    _temp: TempDir,
    drive: PathBuf,
    identity_file: PathBuf,
    passphrase_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new();
        let identity_file = temp.0.join("identity");
        let passphrase_file = temp.0.join("passphrase");
        let drive = temp.0.join("drive");
        write_secret(&identity_file, [0x22; 32]);
        write_secret(&passphrase_file, b"test-pass\n");
        command(vec![
            "init".into(),
            drive.display().to_string(),
            "--identity-file".into(),
            identity_file.display().to_string(),
            "--passphrase-file".into(),
            passphrase_file.display().to_string(),
        ])
        .unwrap();
        Fixture {
            _temp: temp,
            drive,
            identity_file,
            passphrase_file,
        }
    }

    fn args(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "snapshot".into(),
            self.drive.display().to_string(),
            "--identity-file".into(),
            self.identity_file.display().to_string(),
            "--passphrase-file".into(),
            self.passphrase_file.display().to_string(),
        ];
        args.extend(action);
        args
    }

    fn open(&self) -> Engine {
        let identity = read_identity(&self.identity_file).unwrap();
        Engine::open_keystore(self.drive.clone(), "test-pass", identity).unwrap()
    }

    fn member_args(&self, action: Vec<String>) -> Vec<String> {
        let mut args = vec![
            "member".into(),
            self.drive.display().to_string(),
            "--identity-file".into(),
            self.identity_file.display().to_string(),
            "--passphrase-file".into(),
            self.passphrase_file.display().to_string(),
        ];
        args.extend(action);
        args
    }
}

/// Author one file snapshot over the fixture drive, returning its
/// snapshot id.
fn write_file(fixture: &Fixture, name: &str, bytes: &[u8]) -> SnapshotId {
    let identity = read_identity(&fixture.identity_file).unwrap();
    let mut engine = Engine::open_keystore(fixture.drive.clone(), "test-pass", identity).unwrap();
    let mut store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let chunk = store.insert(ObjectKind::Chunk, bytes).unwrap();
    let entry = Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap();
    let tree = Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    engine
        .author_snapshot(&store, tree)
        .unwrap()
        .snapshot()
        .snapshot_id()
}

/// Reads project an empty drive: no heads to list or classify.
#[test]
fn snapshot_reports_describe_a_fresh_drive() {
    let fixture = Fixture::new();
    command(fixture.args(vec!["list".into()])).unwrap();
    command(fixture.args(vec!["heads".into()])).unwrap();

    let engine = fixture.open();
    assert!(
        snapshot_list_report(&engine).unwrap().contains("none"),
        "no live heads yet"
    );
    assert!(
        snapshot_heads_report(&engine).unwrap().contains("none"),
        "no DAG heads yet"
    );
}

/// The list numbers the live head `@1`; the heads view classifies
/// it eligible under the same number.
#[test]
fn snapshot_list_numbers_the_live_head() {
    let fixture = Fixture::new();
    let id = write_file(&fixture, "kept.txt", b"kept");
    command(fixture.args(vec!["list".into()])).unwrap();
    command(fixture.args(vec!["heads".into()])).unwrap();

    let engine = fixture.open();
    let list = snapshot_list_report(&engine).unwrap();
    assert!(list.contains("@1"), "the head is numbered");
    assert!(list.contains(&id.to_string()), "the list names the head");
    let heads = snapshot_heads_report(&engine).unwrap();
    assert!(heads.contains("eligible"), "the head is eligible");
    assert!(heads.contains("@1"), "the number matches the list");
}

/// Author a recovery snapshot grafting `bytes` under `name`,
/// returning its snapshot id: the engine call `recover run` will
/// wrap, exercised here directly so the renderer tests do not
/// depend on the command they motivate.
fn write_recovery(fixture: &Fixture, name: &str, bytes: &[u8]) -> SnapshotId {
    let identity = read_identity(&fixture.identity_file).unwrap();
    let mut engine = Engine::open_keystore(fixture.drive.clone(), "test-pass", identity).unwrap();
    let mut store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let chunk = store.insert(ObjectKind::Chunk, bytes).unwrap();
    let entry = Entry::file(name, bytes.len() as u64, false, vec![chunk]).unwrap();
    let tree = Tree::from_entries(vec![entry])
        .unwrap()
        .insert_into(&mut store)
        .unwrap();
    engine
        .author_recovery_snapshot(&store, tree)
        .unwrap()
        .snapshot()
        .snapshot_id()
}

/// A recovery-flagged head carries its marker in the list while
/// live: the OD-15-4 audit surface.
#[test]
fn snapshot_list_marks_recovery_heads() {
    let fixture = Fixture::new();
    write_file(&fixture, "kept.txt", b"kept");
    let id = write_recovery(&fixture, "grafted.txt", b"grafted");
    command(fixture.args(vec!["list".into()])).unwrap();

    let engine = fixture.open();
    let list = snapshot_list_report(&engine).unwrap();
    assert!(list.contains(&id.to_string()), "the list names the head");
    assert!(list.contains("recovery"), "the recovery flag is marked");
}

/// The marker is also on the heads tip row: the two renderers
/// mark independently. Heads lists tips only, so the marker audits
/// a recovery while it is listed — once history moves past it the
/// snapshot leaves both views (see `docs/cli.md`).
#[test]
fn snapshot_heads_marks_recovery_tips() {
    let fixture = Fixture::new();
    write_file(&fixture, "kept.txt", b"kept");
    let id = write_recovery(&fixture, "grafted.txt", b"grafted");

    let engine = fixture.open();
    let heads = snapshot_heads_report(&engine).unwrap();
    let row = heads
        .lines()
        .find(|line| line.contains(&id.to_string()))
        .expect("the recovery tip is listed");
    assert!(row.contains("eligible"), "still the tip: {row}");
    assert!(row.contains("recovery"), "the flag is marked: {row}");
}

/// The x-only pubkey a 32-byte secret names.
fn device_id_of(secret: &[u8; 32]) -> DeviceId {
    let keys = nostr::key::Keys::new(nostr::key::SecretKey::from_slice(secret).unwrap());
    DeviceId::from_bytes(*keys.public_key().as_bytes())
}

/// The encryption key a 32-byte secret names.
fn encryption_key_of(secret: &[u8; 32]) -> wyrd_format::DeviceEncryptionKey {
    let keys = nostr::key::Keys::new(nostr::key::SecretKey::from_slice(secret).unwrap());
    wyrd_format::DeviceEncryptionKey::from_bytes(*keys.public_key().as_bytes())
}

/// Admit a member device, returning its id.
fn admit_member(fixture: &Fixture, secret: &[u8; 32]) -> DeviceId {
    let id = device_id_of(secret);
    let key = encryption_key_of(secret);
    let out = fixture._temp.0.join(format!("invitation-{id}"));
    command(fixture.member_args(vec![
        "invite".into(),
        id.to_string(),
        key.to_string(),
        out.display().to_string(),
    ]))
    .unwrap();
    id
}

/// Malformed sources and spec lines fail at the argument boundary,
/// before the engine runs.
#[test]
fn snapshot_merge_rejects_malformed_arguments() {
    let fixture = Fixture::new();
    let id = write_file(&fixture, "kept.txt", b"kept");

    for args in [
        vec!["merge".into(), "--head".into(), "not-hex".into()],
        vec!["merge".into(), "--take".into(), "a".into()],
        vec!["merge".into(), "--take".into(), "a=1".into()],
        vec!["merge".into(), "--take".into(), "a/b=@1".into()],
        vec!["merge".into(), "--drop".into(), "a/b".into()],
        vec![
            "merge".into(),
            "--head".into(),
            id.to_string(),
            "--default".into(),
            "@9".into(),
        ],
        vec![
            "merge".into(),
            "--head".into(),
            id.to_string(),
            "--take".into(),
            "a=@1".into(),
            "--drop".into(),
            "a".into(),
        ],
    ] {
        let error = command(fixture.args(args)).unwrap_err();
        assert!(matches!(error, CliError::Usage(_)), "unexpected: {error:?}");
    }
}

/// Merging fewer than two heads fails with the engine's verdict and
/// authors nothing.
#[test]
fn snapshot_merge_without_two_heads_fails_closed() {
    let fixture = Fixture::new();
    let error = command(fixture.args(vec!["merge".into()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::MergeNeedsTwoHeads)),
        "unexpected: {error:?}"
    );
    assert!(
        fixture.open().live_heads().unwrap().is_empty(),
        "nothing authored"
    );

    let id = write_file(&fixture, "kept.txt", b"kept");
    let error =
        command(fixture.args(vec!["merge".into(), "--head".into(), id.to_string()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::MergeNeedsTwoHeads)),
        "unexpected: {error:?}"
    );
    assert_eq!(
        fixture.open().live_heads().unwrap().len(),
        1,
        "the head stands"
    );
}

/// Unknown and doubled sources fail with the engine's verdict.
#[test]
fn snapshot_merge_rejects_bad_sources() {
    let fixture = Fixture::new();
    let id = write_file(&fixture, "kept.txt", b"kept");
    let unknown = SnapshotId::from_bytes([0xFF; 32]);

    let error = command(fixture.args(vec![
        "merge".into(),
        "--head".into(),
        id.to_string(),
        "--head".into(),
        unknown.to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::NotEligibleHead(missing)) if missing == unknown),
        "unexpected: {error:?}"
    );
    let error = command(fixture.args(vec![
        "merge".into(),
        "--head".into(),
        id.to_string(),
        "--head".into(),
        id.to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::DuplicateMergeHead(dupe)) if dupe == id),
        "unexpected: {error:?}"
    );
    assert_eq!(
        fixture.open().live_heads().unwrap().len(),
        1,
        "every refusal authored nothing"
    );
}

/// Planning without two heads fails with the engine's verdict,
/// authoring nothing — including on a headed drive, where no
/// membership freeze diverts the error.
#[test]
fn snapshot_plan_needs_two_heads() {
    let fixture = Fixture::new();
    let error = command(fixture.args(vec!["plan".into()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::MergeNeedsTwoHeads)),
        "unexpected: {error:?}"
    );
    let error =
        command(fixture.args(vec!["plan".into(), "--head".into(), "not-hex".into()])).unwrap_err();
    assert!(matches!(error, CliError::Usage(_)), "unexpected: {error:?}");

    write_file(&fixture, "kept.txt", b"kept");
    let error = command(fixture.args(vec!["plan".into()])).unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::MergeNeedsTwoHeads)),
        "one eligible head is still one head short: {error:?}"
    );
}

/// The frozen hint names the epoch and the resolver when merging
/// stalls on a membership conflict.
#[test]
fn frozen_hint_names_the_conflict() {
    let hint = frozen_merge_hint(2);
    assert!(hint.contains("epoch 2"), "names the frozen epoch");
    assert!(hint.contains("member resolve"), "names the resolver");
}

/// The engine-to-operator seam maps only the freeze to guidance:
/// every other refusal passes through untouched.
#[test]
fn merge_error_mapping_guides_only_the_freeze() {
    let mapped = map_merge_error(EngineError::MergeBlockedByFreeze(2));
    assert!(
        matches!(&mapped, CliError::Usage(hint) if hint.contains("epoch 2")),
        "the freeze becomes usage guidance: {mapped:?}"
    );
    let mapped = map_merge_error(EngineError::MergeNeedsTwoHeads);
    assert!(
        matches!(mapped, CliError::Engine(EngineError::MergeNeedsTwoHeads)),
        "other refusals pass through: {mapped:?}"
    );
}

/// The plan preview names agreed paths and each head's version of
/// conflicted ones over the `@N` basis.
#[test]
fn snapshot_plan_report_renders_versions_per_head() {
    use std::collections::BTreeMap;
    use wyrd_format::{ContentId, EntryContent};
    use wyrd_sync::runtime::{MergePath, MergePlan};
    let first = SnapshotId::from_bytes([0x11; 32]);
    let second = SnapshotId::from_bytes([0x22; 32]);
    let chunk = ContentId::from_bytes([0x33; 32]);
    let entry = Entry::file("a", 3, false, vec![chunk]).unwrap();
    assert!(matches!(entry.content, EntryContent::File { .. }));
    let plan = MergePlan {
        heads: vec![first, second],
        paths: vec![
            MergePath {
                path: "a".to_owned(),
                versions: BTreeMap::from([(first, Some(entry)), (second, None)]),
            },
            MergePath {
                path: "same".to_owned(),
                versions: BTreeMap::from([
                    (
                        first,
                        Some(Entry::file("same", 1, false, vec![chunk]).unwrap()),
                    ),
                    (
                        second,
                        Some(Entry::file("same", 1, false, vec![chunk]).unwrap()),
                    ),
                ]),
            },
        ],
    };
    let report = snapshot_plan_report(&plan);
    assert!(report.contains("merge plan (2 heads)"), "names the basis");
    assert!(
        report.contains("a: conflicted @1=file:3B,1chunks @2=absent"),
        "conflicted row names each version: {report}"
    );
    assert!(report.contains("same: agreed"), "agreed row takes itself");
}

/// The plan report names the source and every row with its reason:
/// the dry run is honest about the full picture or it is not one.
#[test]
fn recover_plan_report_names_every_status_with_its_reason() {
    use wyrd_sync::runtime::{RecoveryPath, RecoveryPlan, RecoveryStatus};

    let chunk = wyrd_format::ContentId::from_bytes([0x33; 32]);
    let row = |path: &str, status: RecoveryStatus| RecoveryPath {
        path: path.to_owned(),
        entry: Entry::file(path, 1, false, vec![chunk]).unwrap(),
        status,
    };
    let from = SnapshotId::from_bytes([0x77; 32]);
    let plan = RecoveryPlan {
        from,
        paths: vec![
            row("ready.txt", RecoveryStatus::Ready),
            row("live.txt", RecoveryStatus::AlreadyLive),
            row("locked.txt", RecoveryStatus::Undecryptable),
            row("gone.txt", RecoveryStatus::Missing),
        ],
    };
    let report = recovery_plan_report(&plan);
    assert!(
        report.contains(&format!("recovery plan (from {from})")),
        "names the source: {report}"
    );
    assert!(report.contains("ready.txt: ready"), "ready row: {report}");
    assert!(
        report.contains("live.txt: already-live"),
        "already-live row with its reason: {report}"
    );
    assert!(
        report.contains("locked.txt: undecryptable"),
        "undecryptable row with its reason: {report}"
    );
    assert!(
        report.contains("gone.txt: missing"),
        "missing row with its reason: {report}"
    );
}

/// `recover plan` over history prints graftable rows; over the live
/// head it reports already-live instead of a graft case.
#[test]
fn recover_plan_renders_source_rows() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let second = write_file(&fixture, "new.txt", b"new");
    command(fixture.args(vec![
        "recover".into(),
        "plan".into(),
        "--from".into(),
        first.to_string(),
    ]))
    .unwrap();

    let engine = fixture.open();
    let store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let report = recovery_plan_report(&engine.recovery_plan(&store, first).unwrap());
    assert!(
        report.contains("old.txt: ready"),
        "history reads ready: {report}"
    );
    let live = recovery_plan_report(&engine.recovery_plan(&store, second).unwrap());
    assert!(
        live.contains("new.txt: already-live"),
        "the live head's own row is already-live: {live}"
    );
}

/// `recover run --take` grafts the selection under the recovery
/// flag, parenting onto the current eligible heads.
#[test]
fn recover_run_grafts_the_take() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let second = write_file(&fixture, "new.txt", b"new");
    command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--take".into(),
        "old.txt".into(),
    ]))
    .unwrap();

    let engine = fixture.open();
    let list = snapshot_list_report(&engine).unwrap();
    assert!(list.contains("recovery"), "the graft is marked: {list}");
    let grafted = engine
        .live_heads()
        .unwrap()
        .into_iter()
        .find(|head| head.snapshot().flags() & wyrd_format::RECOVERY_FLAG != 0)
        .expect("a recovery head is live");
    assert_eq!(
        grafted.snapshot().parents,
        vec![second],
        "parents are the current eligible heads"
    );
}

/// `--all` grafts the whole source tree in one run.
#[test]
fn recover_run_all_grafts_the_whole_tree() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    write_file(&fixture, "new.txt", b"new");
    command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--all".into(),
    ]))
    .unwrap();

    let engine = fixture.open();
    let grafted = engine
        .live_heads()
        .unwrap()
        .into_iter()
        .find(|head| head.snapshot().flags() & wyrd_format::RECOVERY_FLAG != 0)
        .expect("a recovery head is live");
    let store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let bytes = store.get(&grafted.snapshot().tree).unwrap().unwrap();
    let names: Vec<_> = Tree::decode(&bytes)
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.name.as_str().to_owned())
        .collect();
    assert_eq!(names, vec!["old.txt"], "the whole source tree grafts");
}

/// `--content` grafts explicitly named bytes under their hex name,
/// for content whose path the operator no longer knows.
#[test]
fn recover_run_content_grafts_under_its_hex_name() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    write_file(&fixture, "new.txt", b"new");
    let loose = {
        let mut store = FsObjectStore::open(fixture.drive.clone()).unwrap();
        store.insert(ObjectKind::Chunk, b"loose").unwrap()
    };
    command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--content".into(),
        loose.to_string(),
    ]))
    .unwrap();

    let engine = fixture.open();
    let grafted = engine
        .live_heads()
        .unwrap()
        .into_iter()
        .find(|head| head.snapshot().flags() & wyrd_format::RECOVERY_FLAG != 0)
        .expect("a recovery head is live");
    let store = FsObjectStore::open(fixture.drive.clone()).unwrap();
    let bytes = store.get(&grafted.snapshot().tree).unwrap().unwrap();
    let names: Vec<_> = Tree::decode(&bytes)
        .unwrap()
        .entries()
        .iter()
        .map(|entry| entry.name.as_str().to_owned())
        .collect();
    assert_eq!(
        names,
        vec![loose.to_string()],
        "the content grafts under its hex name"
    );
}

/// Running with no selection names itself and commits nothing.
#[test]
fn recover_run_refuses_when_nothing_is_selected() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let before = fixture.open().live_heads().unwrap().len();
    let error = command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::RecoveryEmptySelection)),
        "unexpected: {error:?}"
    );
    assert_eq!(
        fixture.open().live_heads().unwrap().len(),
        before,
        "refusals commit nothing"
    );
}

/// Unknown paths and unknown content ids fail closed with nothing
/// committed.
#[test]
fn recover_run_refuses_an_unrecoverable_selection() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let before = fixture.open().live_heads().unwrap().len();
    let error = command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--take".into(),
        "nope.txt".into(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::UnknownRecoveryPath(_))),
        "unexpected: {error:?}"
    );
    let error = command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--content".into(),
        "77".repeat(32),
    ]))
    .unwrap_err();
    assert!(
        matches!(
            error,
            CliError::Engine(EngineError::UnknownRecoveryContent(_))
        ),
        "unexpected: {error:?}"
    );
    assert_eq!(
        fixture.open().live_heads().unwrap().len(),
        before,
        "refusals commit nothing"
    );
}

/// `--all` with `--take` lines contradicts itself at the argument
/// boundary, before the engine runs.
#[test]
fn recover_run_rejects_all_with_take() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let error = command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--all".into(),
        "--take".into(),
        "old.txt".into(),
    ]))
    .unwrap_err();
    assert!(matches!(error, CliError::Usage(_)), "unexpected: {error:?}");
}

/// A non-owner fails closed with the engine's refusal and the heads
/// are unchanged: the pre-check surfaces before any selection work.
#[test]
fn recover_run_by_a_non_owner_fails_closed() {
    let fixture = Fixture::new();
    let first = write_file(&fixture, "old.txt", b"old");
    let member = admit_member(&fixture, &[0x44; 32]);
    command(fixture.member_args(vec!["set-owner".into(), member.to_string()])).unwrap();

    let before = snapshot_heads_report(&fixture.open()).unwrap();
    let error = command(fixture.args(vec![
        "recover".into(),
        "run".into(),
        "--from".into(),
        first.to_string(),
        "--take".into(),
        "old.txt".into(),
    ]))
    .unwrap_err();
    assert!(
        matches!(error, CliError::Engine(EngineError::RecoveryNotOwner)),
        "unexpected: {error:?}"
    );
    assert_eq!(
        snapshot_heads_report(&fixture.open()).unwrap(),
        before,
        "the failed run commits nothing"
    );
}
