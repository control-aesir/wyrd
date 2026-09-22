use super::*;

pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        // Process id plus an atomic counter: wall-clock nanos collide
        // under parallel nextest (observed: StoreLocked on a sibling's
        // directory), while a counter is unique by construction.
        // Remove first so a crashed run's leftovers never poison init.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let path = env::temp_dir().join(format!("wyrd-daemon-cli-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Scoped `RUST_LOG` removal: the diagnostics tests need the default
/// filter, not ambient environment. Restores on drop so a panicking
/// assert cannot leak the mutation into sibling tests sharing the
/// process.
pub(crate) struct WithoutRustLog {
    previous: Option<String>,
}

impl WithoutRustLog {
    pub(crate) fn take() -> Self {
        let previous = std::env::var("RUST_LOG").ok();
        std::env::remove_var("RUST_LOG");
        WithoutRustLog { previous }
    }
}

impl Drop for WithoutRustLog {
    fn drop(&mut self) {
        if let Some(value) = self.previous.take() {
            std::env::set_var("RUST_LOG", value);
        }
    }
}

/// How long a shutdown waits for the mount thread before
/// detaching: long enough for a healthy unmount-and-join
/// sequence, short enough that a wedged FUSE thread fails the
/// test instead of hanging CI.
pub(crate) const JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Wait up to `timeout` for the mount thread, returning its
/// outcome; on expiry the handle is dropped (detaching the
/// thread) and `None` is returned.
pub(crate) fn reclaim(
    server: std::thread::JoinHandle<Result<(), CliError>>,
    timeout: std::time::Duration,
) -> Option<std::thread::Result<Result<(), CliError>>> {
    let deadline = std::time::Instant::now() + timeout;
    while !server.is_finished() && std::time::Instant::now() <= deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if server.is_finished() {
        Some(server.join())
    } else {
        None
    }
}

pub(crate) fn write_secret(path: &Path, bytes: impl AsRef<[u8]>) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
