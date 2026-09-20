use super::probes::{
    check_macfuse_runtime, check_mountpoint, probe_macfuse_runtime, select_macfuse_runtime,
    MacfuseProbe,
};
use super::tests_harness::{reclaim, TempDir, JOIN_TIMEOUT};
use super::*;

/// `reclaim` returns a finished thread's outcome, success or
/// mount error alike.
#[test]
fn reclaim_returns_a_finished_threads_outcome() {
    let ok = std::thread::spawn(|| Ok(()));
    assert!(matches!(reclaim(ok, JOIN_TIMEOUT), Some(Ok(Ok(())))));
    let failed = std::thread::spawn(|| Err(CliError::Mount(std::io::Error::other("boom"))));
    assert!(matches!(reclaim(failed, JOIN_TIMEOUT), Some(Ok(Err(_)))));
}

/// `reclaim` gives up after the bound instead of hanging: a
/// blocked thread yields `None` promptly, and dropping the
/// sender lets it exit so nothing lingers past the test.
#[test]
fn reclaim_detaches_past_the_deadline() {
    let (send, recv) = std::sync::mpsc::channel::<()>();
    let blocked = std::thread::spawn(move || {
        let _ = recv.recv();
        Ok(())
    });
    let bound = std::time::Duration::from_millis(200);
    let start = std::time::Instant::now();
    assert!(
        reclaim(blocked, bound).is_none(),
        "a wedged thread detaches"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "the rejoin is bounded"
    );
    drop(send);
}

/// Each mount stage names itself: serving, bulk, preflight, and
/// the FUSE session render distinct prefixes, so a failure can
/// never again report every stage as "FUSE mount failed".
#[test]
fn mount_stages_name_themselves() {
    let serving = CliError::Serving(std::io::Error::other("down"));
    let bulk = CliError::Bulk(std::io::Error::other("down"));
    let preflight = CliError::Preflight("kext missing".into());
    let mount = CliError::Mount(std::io::Error::other("down"));
    for (error, prefix) in [
        (serving, "serving endpoint failed"),
        (bulk, "bulk source failed"),
        (preflight, "macOS FUSE preflight failed"),
        (mount, "FUSE mount failed"),
    ] {
        assert!(
            format!("{error}").starts_with(prefix),
            "staged error must name its stage: {error}"
        );
    }
}

/// The mountpoint probe accepts a directory and names anything
/// else: fuser's bare ENOENT never reaches the user.
#[test]
fn mountpoint_probe_names_missing_or_file() {
    let temp = TempDir::new();
    assert!(check_mountpoint(&temp.0).is_ok());
    let missing = temp.0.join("nope");
    assert!(matches!(check_mountpoint(&missing), Err(reason) if reason.contains("does not exist")));
    let file = temp.0.join("file");
    fs::write(&file, b"x").unwrap();
    assert!(matches!(check_mountpoint(&file), Err(reason) if reason.contains("not a directory")));
}

/// The runtime probe distinguishes absent macFUSE from an
/// unloaded kext, and passes when both probes hit.
#[test]
fn runtime_probe_distinguishes_absent_from_unloaded() {
    let temp = TempDir::new();
    let bundle = temp.0.join("macfuse.fs");
    let dev = temp.0.join("dev");
    fs::create_dir_all(&dev).unwrap();
    assert!(
        matches!(check_macfuse_runtime(&bundle, &dev), Err(reason) if reason.contains("not installed"))
    );
    fs::create_dir_all(&bundle).unwrap();
    assert!(
        matches!(check_macfuse_runtime(&bundle, &dev), Err(reason) if reason.contains("not loaded"))
    );
    fs::write(dev.join("macfuse0"), b"").unwrap();
    assert!(check_macfuse_runtime(&bundle, &dev).is_ok());
}

/// Candidate selection probes bundle and kext as a pair and falls
/// through to later layouts: a missing or corrupt first bundle never
/// shadows a valid second one, and neither does a first bundle
/// directory whose kext is down while the second pair is valid.
#[test]
fn bundle_selection_falls_through_to_later_layouts() {
    let temp = TempDir::new();
    let first = temp.0.join("macfuse.fs");
    let second = temp.0.join("fuse.fs");
    let dev1 = temp.0.join("dev1");
    let dev2 = temp.0.join("dev2");
    fs::create_dir_all(&dev1).unwrap();
    fs::create_dir_all(&dev2).unwrap();
    assert!(
        matches!(select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]), Err(reason) if reason.contains("not installed"))
    );
    fs::create_dir_all(&second).unwrap();
    fs::write(dev2.join("macfuse0"), b"").unwrap();
    assert_eq!(
        select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
        second
    );
    fs::write(&first, b"stale").unwrap();
    assert_eq!(
        select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
        second
    );
    // The stale-directory case: the first bundle exists as a
    // directory but its kext is down, while the second pair is
    // fully valid. Selection must skip the first pair.
    fs::remove_file(&first).unwrap();
    fs::create_dir_all(&first).unwrap();
    assert_eq!(
        select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
        second
    );
    // And a valid first pair still wins when both are usable.
    fs::write(dev1.join("macfuse0"), b"").unwrap();
    assert_eq!(
        select_macfuse_runtime(&[(&first, &dev1), (&second, &dev2)]).unwrap(),
        first
    );
}

/// The typed probe names each state without string matching: bundle
/// absence, kext absence, and readiness are distinct variants.
#[test]
fn typed_probe_names_each_state() {
    let temp = TempDir::new();
    let bundle = temp.0.join("macfuse.fs");
    let dev = temp.0.join("dev");
    fs::create_dir_all(&dev).unwrap();
    assert_eq!(
        probe_macfuse_runtime(&bundle, &dev),
        MacfuseProbe::BundleMissing
    );
    fs::create_dir_all(&bundle).unwrap();
    assert_eq!(
        probe_macfuse_runtime(&bundle, &dev),
        MacfuseProbe::KextMissing
    );
    fs::write(dev.join("macfuse0"), b"").unwrap();
    assert_eq!(probe_macfuse_runtime(&bundle, &dev), MacfuseProbe::Ready);
}
