use std::path::PathBuf;
use std::sync::atomic::Ordering;

use crate::view::{confine_symlink_target, ConfinementError, ViewError, MAX_SYMLINK_WORK};

use super::tests_harness::{assert_no_staging, drive, tmp, FakeNode, FakeView};
use super::{export_tree, ExportError};

#[test]
fn exports_the_whole_tree_byte_identical() {
    let (view, expected) = drive();
    let dest = tmp();
    let out = dest.join("out");

    let report = export_tree(&view, &out).unwrap();

    assert_eq!(report.files, 6, "hello, big, tool, nested, opt@1, opt@2");
    assert_eq!(report.dirs, 3, "root, sub, empty");
    assert_eq!(report.symlinks, 2, "link and sub/back");
    assert_eq!(report.conflicts, 1);
    assert_eq!(
        report.bytes,
        expected
            .values()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>()
    );
    for (rel, bytes) in &expected {
        assert_eq!(
            &std::fs::read(out.join(rel)).unwrap(),
            bytes,
            "mismatch at {rel}"
        );
    }
    assert!(out.join("empty").is_dir(), "empty dirs survive");
    assert_eq!(
        std::fs::read_link(out.join("link")).unwrap(),
        PathBuf::from("hello.txt")
    );
    assert_eq!(
        std::fs::read_link(out.join("sub").join("back")).unwrap(),
        PathBuf::from("../hello.txt"),
        "confined relative targets land verbatim"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(out.join("tool.sh"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "executable bit preserved");
        let mode = std::fs::metadata(out.join("hello.txt"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "regular files stay regular");
    }

    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn refuses_a_populated_destination() {
    let (view, _) = drive();
    let dest = tmp();
    std::fs::write(dest.join("mine.txt"), b"not yours").unwrap();

    let error = export_tree(&view, &dest).unwrap_err();

    assert!(
        matches!(error, ExportError::DestinationNotEmpty(_)),
        "unexpected: {error:?}"
    );
    assert_eq!(
        std::fs::read(dest.join("mine.txt")).unwrap(),
        b"not yours",
        "the existing tree is untouched"
    );
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_on_remote_only_content() {
    let (mut view, _) = drive();
    view.mark_missing(0);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

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
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_when_a_stored_name_meets_a_versioned_sibling() {
    let mut view = FakeView::default();
    let clash = view.file(b"real file", false);
    let ver = view.file(b"version", false);
    view.set_root(vec![
        ("x".to_owned(), FakeNode::Conflict(vec![(1u8, ver)])),
        ("x@1".to_owned(), clash),
    ]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

    assert!(
        matches!(error, ExportError::NameCollision(_)),
        "unexpected: {error:?}"
    );
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn failed_root_lookup_leaves_no_staging() {
    let (mut view, _) = drive();
    view.fail_root = true;
    let dest = tmp();
    let out = dest.join("out");

    let error = export_tree(&view, &out).unwrap_err();

    assert!(
        matches!(
            error,
            ExportError::View {
                source: ViewError::InvalidPath,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    // Staging was claimed before the lookup ran: nothing was
    // written into it, and the single cleanup scope removed it.
    assert!(!out.exists(), "the destination is absent, not partial");
    assert_no_staging(&out);
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn refuses_absolute_and_escaping_symlink_targets() {
    let mut view = FakeView::default();
    view.set_root(vec![(
        "abs".to_owned(),
        FakeNode::Symlink("/etc/passwd".to_owned()),
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::Absolute,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));

    let mut view = FakeView::default();
    let esc = view.dir(vec![(
        "esc".to_owned(),
        // Two pops from depth 1: above the drive root.
        FakeNode::Symlink("../../evil".to_owned()),
    )]);
    view.set_root(vec![("sub".to_owned(), esc)]);

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::EscapesRoot,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn refuses_chained_symlink_escape() {
    let mut view = FakeView::default();
    let b = view.dir(vec![
        ("s".to_owned(), FakeNode::Symlink("../..".to_owned())),
        (
            "link".to_owned(),
            FakeNode::Symlink("s/../../outside".to_owned()),
        ),
    ]);
    let a = view.dir(vec![("b".to_owned(), b)]);
    view.set_root(vec![("a".to_owned(), a)]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::EscapesRoot,
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn preserves_symlink_lookup_failures_in_export_diagnostics() {
    let mut view = FakeView {
        lookup_error: Some(("target".to_owned(), ViewError::Corrupt)),
        ..FakeView::default()
    };
    view.set_root(vec![(
        "link".to_owned(),
        FakeNode::Symlink("target".to_owned()),
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(
        matches!(
            error,
            ExportError::Symlink {
                source: ConfinementError::Lookup {
                    source: ViewError::Corrupt
                },
                ..
            }
        ),
        "unexpected: {error:?}"
    );
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn pathological_symlink_target_is_work_bounded() {
    let mut view = FakeView {
        child_work: Some(MAX_SYMLINK_WORK),
        ..FakeView::default()
    };
    view.set_root(Vec::new());
    let before = view.child_lookup_count.load(Ordering::Relaxed);

    assert!(matches!(
        confine_symlink_target(&view, "link", "z"),
        Err(ConfinementError::WorkLimit {
            observed,
            max: MAX_SYMLINK_WORK,
        }) if observed > MAX_SYMLINK_WORK
    ));
    assert_eq!(view.child_lookup_count.load(Ordering::Relaxed) - before, 1);
}

#[test]
fn export_shares_symlink_work_budget_across_entries() {
    let mut view = FakeView {
        child_work: Some(MAX_SYMLINK_WORK / 2),
        ..FakeView::default()
    };
    view.set_root(vec![
        ("one".to_owned(), FakeNode::Symlink("x".to_owned())),
        ("two".to_owned(), FakeNode::Symlink("x".to_owned())),
    ]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();
    assert!(matches!(
        error,
        ExportError::Symlink {
            source: ConfinementError::WorkLimit {
                observed,
                max: MAX_SYMLINK_WORK,
            },
            ..
        } if observed > MAX_SYMLINK_WORK
    ));
    assert_no_staging(&dest.join("out"));
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_on_short_reads() {
    let mut view = FakeView::default();
    view.arena.push(b"abc".to_vec());
    view.set_root(vec![(
        "short.txt".to_owned(),
        FakeNode::File {
            arena: 0,
            executable: false,
            // Declares 100 bytes, streams 3.
            declared: Some(100),
        },
    )]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

    match error {
        ExportError::SizeMismatch {
            expected, actual, ..
        } => assert_eq!((expected, actual), (100, 3)),
        other => panic!("unexpected: {other:?}"),
    }
    assert!(!dest.join("out").exists(), "no truncated file lands");
    std::fs::remove_dir_all(dest).unwrap();
}

#[test]
fn fails_closed_beyond_max_depth() {
    let mut view = FakeView::default();
    let leaf = view.file(b"deep", false);
    let mut node = leaf;
    // Single-letter names: the walk must trip the depth cap long
    // before the filesystem path limit matters.
    for level in 0..260 {
        let name = ((b'a' + (level % 26) as u8) as char).to_string();
        node = view.dir(vec![(name, node)]);
    }
    view.set_root(vec![("top".to_owned(), node)]);
    let dest = tmp();

    let error = export_tree(&view, &dest.join("out")).unwrap_err();

    assert!(
        matches!(error, ExportError::TooDeep(_)),
        "unexpected: {error:?}"
    );
    assert!(!dest.join("out").exists());
    std::fs::remove_dir_all(dest).unwrap();
}
