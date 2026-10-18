use std::sync::Mutex;
use std::time::SystemTime;

use crate::view::ViewError;

use super::staging::{
    now_nanos, sweep_staging_with_probe, sweep_stale_staging, HEARTBEAT_FILE, HEARTBEAT_MAGIC,
};
use super::tests_harness::{assert_no_staging, drive, tmp};
use super::{export_tree, ExportError};

#[test]
fn stale_staging_is_swept_by_the_next_export() {
    let (view, expected) = drive();
    let dest = tmp();
    let out = dest.join("out");
    // A crashed predecessor's staging: a valid exporter marker
    // with an ancient heartbeat, plus junk that must never merge
    // into the published tree.
    let staging = out.with_file_name("out.wyrd-export.1.1");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n1\n"),
    )
    .unwrap();
    std::fs::write(staging.join("junk.txt"), b"stale").unwrap();

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6);
    assert!(!staging.exists(), "the crashed run's staging is gone");
    for (rel, bytes) in &expected {
        assert_eq!(
            &std::fs::read(out.join(rel)).unwrap(),
            bytes,
            "mismatch at {rel}"
        );
    }
    assert!(
        out.read_dir()
            .unwrap()
            .all(|entry| entry.unwrap().file_name() != "junk.txt"),
        "the crashed run's junk never merges"
    );
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fresh_staging_is_left_alone() {
    let (view, _) = drive();
    let dest = tmp();
    let out = dest.join("out");
    // A live concurrent export's staging: a current heartbeat.
    // The sweep must not touch it, and our own export proceeds
    // alongside in its own staging.
    let live = out.with_file_name("out.wyrd-export.2.2");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(
        live.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now())),
    )
    .unwrap();

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6);
    assert!(live.is_dir(), "a live export's staging is untouched");
    assert!(out.is_dir(), "our own export published normally");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn heartbeat_refreshed_before_removal_spares_the_directory() {
    // The classification/removal race, deterministically: the
    // staging reads stale, the owner beats in the window (the
    // probe), and the recheck must spare it. Without the recheck
    // this test deletes a live run's tree.
    let dest = tmp();
    let out = dest.join("out");
    let staging = out.with_file_name("out.wyrd-export.3.3");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(
        staging.join(HEARTBEAT_FILE),
        format!("{HEARTBEAT_MAGIC}\n1\n"),
    )
    .unwrap();

    sweep_staging_with_probe(&out, SystemTime::now(), &mut |path| {
        assert_eq!(path, staging);
        std::fs::write(
            staging.join(HEARTBEAT_FILE),
            format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now())),
        )
        .unwrap();
    })
    .unwrap();

    assert!(staging.is_dir(), "the refreshed run survives the sweep");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn unparsable_heartbeat_with_fresh_dir_survives() {
    // A torn or foreign marker must never read as stale on its
    // own: only a valid exporter marker authorizes deletion, and
    // marker-less directories are left for manual cleanup.
    let dest = tmp();
    let out = dest.join("out");
    let staging = out.with_file_name("out.wyrd-export.4.4");
    std::fs::create_dir_all(&staging).unwrap();
    std::fs::write(staging.join(HEARTBEAT_FILE), b"\0 torn \0").unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(staging.is_dir(), "garbage marker alone sweeps nothing");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn same_prefixed_user_directories_survive() {
    // Ownership proof needs the exact generated shape: a
    // same-prefixed user directory survives even holding a valid
    // exporter marker with an ancient heartbeat — prefix without
    // the generated shape is not proof of ownership.
    let dest = tmp();
    let out = dest.join("out");
    let user = out.with_file_name("out.wyrd-export.backup");
    std::fs::create_dir_all(&user).unwrap();
    std::fs::write(user.join(HEARTBEAT_FILE), format!("{HEARTBEAT_MAGIC}\n1\n")).unwrap();
    std::fs::write(user.join("mine.txt"), b"not yours").unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(user.is_dir(), "user directories are never swept");
    assert_eq!(std::fs::read(user.join("mine.txt")).unwrap(), b"not yours");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn markerless_shaped_directories_are_left_for_manual_cleanup() {
    // A crash between staging creation and the first marker write
    // leaves a shaped directory with no marker at all: without
    // proof of ownership the sweep must leave it, whatever its
    // age. (Un-ageable in-test without filetime; the rule is the
    // marker requirement itself — no marker, no deletion, ever.)
    let dest = tmp();
    let out = dest.join("out");
    let orphan = out.with_file_name("out.wyrd-export.9.9");
    std::fs::create_dir_all(&orphan).unwrap();

    sweep_stale_staging(&out, SystemTime::now()).unwrap();

    assert!(orphan.is_dir(), "markerless dirs need a human");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn failed_export_leaves_no_partial_tree() {
    let (mut view, _) = drive();
    // `big.bin` is the third root child: `hello.txt` lands in
    // staging first, then the walk fails — the regression the
    // first-child-missing test never exercises.
    view.mark_missing(2);
    let dest = tmp();
    let out = dest.join("out");

    let error = export_tree(&view, &out).unwrap_err();

    assert!(
        matches!(
            error,
            ExportError::View {
                source: ViewError::NotMaterialized { .. },
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert!(!out.exists(), "the destination is absent, not partial");
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn failed_export_preserves_a_preexisting_empty_destination() {
    let (mut view, _) = drive();
    view.mark_missing(2);
    let dest = tmp();
    let out = dest.join("out");
    std::fs::create_dir_all(&out).unwrap();

    let error = export_tree(&view, &out).unwrap_err();

    assert!(
        matches!(
            error,
            ExportError::View {
                source: ViewError::NotMaterialized { .. },
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert!(
        out.is_dir() && out.read_dir().unwrap().next().is_none(),
        "the pre-existing destination is still there and still empty"
    );
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn concurrent_exports_never_share_staging() {
    // Two exports to the same destination, overlapped
    // deterministically: A parks in its first read (past staging
    // claim and heartbeat) and stays parked while B runs to
    // completion, then resumes. Staging names are unique, so B's
    // entry sweep must leave A's live tree alone; at publish time
    // exactly one rename wins — B published first, so A fails
    // with the destination rule, and `dest` holds B's complete
    // tree.
    let (mut view_a, _) = drive();
    let (parked_tx, parked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    view_a.read_park = Some((parked_tx, Mutex::new(release_rx)));
    let (view_b, _) = drive();
    let dest = tmp();
    let out = dest.join("out");

    std::thread::scope(|scope| {
        let handle = scope.spawn(|| export_tree(&view_a, &out));
        // A is parked in `read`, holding claimed staging with a
        // fresh heartbeat. It cannot proceed until released below,
        // so B's whole run overlaps A's parked walk.
        parked_rx.recv().unwrap();
        let report_b = export_tree(&view_b, &out).unwrap();
        assert_eq!(report_b.files, 6, "B completes while A is parked");
        // B's sweep ran against A's live staging and left it.
        let live: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .into_string()
                    .unwrap()
                    .starts_with("out.wyrd-export.")
            })
            .collect();
        assert_eq!(live.len(), 1, "A's staging survived B's sweep");
        // Release A: it completes its walk into its own staging,
        // then loses the publish race — B's tree populates dest.
        release_tx.send(()).unwrap();
        let error = handle.join().unwrap().unwrap_err();
        assert!(
            matches!(error, ExportError::DestinationNotEmpty(_)),
            "unexpected: {error:?}"
        );
    });

    assert_eq!(
        std::fs::read(out.join("hello.txt")).unwrap(),
        b"hello, wyrd",
        "the destination holds one complete tree"
    );
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}
