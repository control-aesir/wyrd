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
