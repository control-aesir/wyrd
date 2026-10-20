use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::ExportError;

/// Liveness marker for one export run: a timestamp file in the
/// run's own staging container, rewritten as the walk progresses. A
/// later export's sweep reads it to tell crashed runs (stale
/// heartbeat, safe to remove) from live ones (fresh heartbeat, never
/// touched). The marker lives in the container next to the payload
/// subdirectory — never inside the payload — so it shares the run's
/// fate without ever sharing a namespace with user content: the
/// payload alone is renamed into place, and no exporter-chosen name
/// inside the walked tree can collide with, truncate, or delete a
/// stored file. Every legal name stays representable, including
/// `.wyrd-heartbeat` and `.wyrd-heartbeat.tmp`. The marker is
/// written by exactly one owner, so no coordination beyond the
/// filesystem is needed.
///
/// The marker carries a magic value plus the timestamp, and staging
/// names follow an exact generated shape (see [`staging_shape`]):
/// the sweep deletes only directories proving exporter ownership.
/// A user directory that merely looks reserved, or a staging
/// directory whose marker is missing or malformed, is left for
/// manual cleanup — `remove_dir_all` on user-selected turf without
/// proof of ownership is not a tradeoff the sweep may make. The one
/// accepted leak is a crash between staging creation and the first
/// marker write (microseconds, before any walk output exists).
///
/// Updates are atomic (write-then-rename), never truncate-in-place:
/// a concurrent reader sees the old complete marker or the new
/// complete one, never a torn file. Without that, a sweeper reading
/// mid-rewrite would misread a live run as marker-less. Both the
/// marker and its rename sibling live in the container, outside the
/// payload, so the atomic update can never observe user content.
pub(super) const HEARTBEAT_FILE: &str = ".wyrd-heartbeat";

/// The payload subdirectory of a staging container: the walked tree
/// lands here, and only here is renamed into place on success. The
/// name is exporter-chosen and invisible after publish (the payload
/// itself becomes `dest`), so it can never collide with user
/// content — user names live one level down, control state one
/// level up.
pub(super) const PAYLOAD_DIR: &str = "tree";

/// A heartbeat older than this marks its staging as crashed: no
/// healthy export goes this long without 128KiB of progress, while a
/// stalled one is effectively dead. An hour also keeps laptop-suspend
/// false positives rare without letting crash leftovers linger for
/// days. Future timestamps (clock skew) are never stale — leaving a
/// live export alone is always the safe direction.
const STALE_AFTER: Duration = Duration::from_secs(3600);

/// Magic opening the heartbeat marker: the sweep deletes only
/// staging whose marker opens with exactly this line. Anything else
/// — a user directory, a foreign tool's output, tampering — is not
/// provably ours and is left alone.
pub(super) const HEARTBEAT_MAGIC: &str = "WYRD-EXPORT-HEARTBEAT-v1";

/// Whether `remainder` (a staging name with the `<stem>.wyrd-export.`
/// prefix stripped) has the exact generated shape:
/// `<digits>.<digits>`. Shape alone never authorizes deletion (the
/// marker does that); it only keeps obvious non-candidates out of
/// marker parsing.
fn staging_shape(remainder: &str) -> bool {
    match remainder.split_once('.') {
        Some((first, second)) => {
            !first.is_empty()
                && !second.is_empty()
                && !second.contains('.')
                && first.bytes().all(|byte| byte.is_ascii_digit())
                && second.bytes().all(|byte| byte.is_ascii_digit())
        }
        None => false,
    }
}

/// Claim a staging container for one export invocation: a uniquely
/// named sibling of `dest` (`<name>.wyrd-export.<pid>.<nanos>`), so
/// concurrent runs never share a tree. The container holds the
/// heartbeat marker and the payload subdirectory (see
/// [`staging_payload`]) side by side; only the payload publishes.
/// Parents are created; the staging itself is `create_dir`, retried
/// on the vanishingly narrow same-nanosecond collision.
pub(super) fn claim_staging(dest: &Path) -> Result<PathBuf, ExportError> {
    let (stem, parent) = staging_parts(dest);
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(&parent).map_err(|source| ExportError::Io {
            path: parent.clone(),
            source,
        })?;
    }
    for _ in 0..3 {
        let staging = parent.join(format!(
            "{stem}.wyrd-export.{}.{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|time| time.as_nanos())
                .unwrap_or(0)
        ));
        match fs::create_dir(&staging) {
            Ok(()) => return Ok(staging),
            Err(collision) if collision.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(ExportError::Io {
                    path: staging,
                    source,
                });
            }
        }
    }
    Err(ExportError::Io {
        path: dest.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not claim a unique staging directory",
        ),
    })
}

/// Split `dest` into the staging stem and parent: `<parent>/<stem>`
/// stages as `<parent>/<stem>.wyrd-export.<unique>`.
fn staging_parts(dest: &Path) -> (String, PathBuf) {
    let stem = dest
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("export")
        .to_owned();
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    (stem, parent)
}

/// The payload subdirectory of a staging container: the walked tree
/// lands here, and only this directory is renamed into place (see
/// [`PAYLOAD_DIR`]).
pub(super) fn staging_payload(staging: &Path) -> PathBuf {
    staging.join(PAYLOAD_DIR)
}

/// Remove crashed runs' staging siblings of `dest`: entries with
/// the exact generated shape whose marker proves exporter ownership
/// and whose heartbeat is stale (see [`is_stale`]). Deletion needs
/// both — shape without a valid marker, or a valid marker that is
/// fresh, is always left alone. A missing parent means there is
/// nothing to sweep; anything else failing here fails the export,
/// fail-closed.
pub(super) fn sweep_stale_staging(dest: &Path, now: SystemTime) -> Result<(), ExportError> {
    sweep_staging_with_probe(dest, now, &mut |_| {})
}

/// The sweep with a test seam: `probe` runs between stale
/// classification and removal, so a test can refresh the heartbeat
/// in that window and prove the recheck spares the directory. The
/// production probe is a no-op.
pub(super) fn sweep_staging_with_probe(
    dest: &Path,
    now: SystemTime,
    probe: &mut dyn FnMut(&Path),
) -> Result<(), ExportError> {
    let (stem, parent) = staging_parts(dest);
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let entries = match fs::read_dir(&parent) {
        Ok(entries) => entries,
        Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ExportError::Io {
                path: parent,
                source,
            });
        }
    };
    let prefix = format!("{stem}.wyrd-export.");
    for entry in entries {
        let path = entry
            .map_err(|source| ExportError::Io {
                path: parent.clone(),
                source,
            })?
            .path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        // Ownership proof before anything destructive: the exact
        // generated shape, then a valid exporter marker. A
        // same-prefixed user directory fails the shape; a pre-marker
        // crashed run, or tampering, fails the marker — both are left
        // for manual cleanup, never auto-deleted.
        if !staging_shape(&name[prefix.len()..]) {
            continue;
        }
        if !is_stale(&path, now) {
            continue;
        }
        probe(&path);
        // Recheck immediately before removal: a heartbeat refreshed
        // after classification (a live run beating in the window)
        // spares the directory. The residual race — a refresh landing
        // between this recheck and the removal — costs a run stalled
        // past the lease its staging, and it fails loudly on its next
        // filesystem op; `dest` itself is never partial. That window
        // is one re-read wide, not one lease wide.
        if !is_stale(&path, now) {
            continue;
        }
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            // Vanished mid-sweep: its owner published or cleaned it
            // concurrently — the desired end state already holds.
            Err(vanished) if vanished.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ExportError::Io { path, source });
            }
        }
    }
    Ok(())
}

/// Whether a staging sibling belongs to a crashed run: it carries a
/// valid exporter marker (see [`HEARTBEAT_MAGIC`]) whose timestamp is
/// older than [`STALE_AFTER`].
///
/// The guarantee is scoped, and the scope is the point: this
/// predicate must never produce deletion of a run progressing
/// within the lease — heartbeats flow per window and entry, so a
/// healthy run's marker is always fresh at every recheck. It does
/// not, and cannot, distinguish a run stalled past the lease that
/// resumes in the recheck-to-removal window; that run fails loudly
/// on its next filesystem op instead. Marker-less or malformed
/// directories are never stale here, whatever their age: without
/// proof of ownership there is nothing to prove them crashed.
/// Heartbeat updates are atomic renames, so a reader never sees a
/// torn marker — only complete old or new timestamps.
fn is_stale(staging: &Path, now: SystemTime) -> bool {
    let beat = fs::read_to_string(staging.join(HEARTBEAT_FILE))
        .ok()
        .and_then(|text| read_marker(&text));
    match beat {
        Some(beat) => now_nanos(now).saturating_sub(beat) > STALE_AFTER.as_nanos(),
        None => false,
    }
}

/// Parse a heartbeat marker: exactly the magic line plus a timestamp
/// line. Anything else — empty, torn, foreign, tampered — parses as
/// absent, and absent markers are never stale.
fn read_marker(text: &str) -> Option<u128> {
    let (magic, rest) = text.split_once('\n')?;
    if magic != HEARTBEAT_MAGIC {
        return None;
    }
    rest.trim().parse::<u128>().ok()
}

/// Nanoseconds since the epoch for heartbeat timestamps. Unreadable
/// clocks read as zero — ancient, hence sweepable — which is the
/// safe direction for a run that cannot even tell time.
pub(super) fn now_nanos(now: SystemTime) -> u128 {
    now.duration_since(UNIX_EPOCH)
        .map(|time| time.as_nanos())
        .unwrap_or(0)
}

/// One run's heartbeat writer: rewrites the timestamp marker as the
/// walk progresses, atomically (write a sibling, rename over the
/// marker) so concurrent readers never see a torn value. Beats are
/// throttled to every 64th call: the lease is an hour, so per-window
/// markers would buy nothing but metadata traffic on large trees,
/// while the claim-time beat covers short runs outright. Write
/// failures surface as I/O errors, which is also what a run
/// observes when its staging disappears underneath it — either way
/// the export fails loudly instead of publishing from a tree it no
/// longer owns.
#[derive(Debug)]
pub(super) struct Heartbeat {
    path: PathBuf,
    calls: u64,
}
impl Heartbeat {
    pub(super) fn new(path: PathBuf) -> Self {
        Heartbeat { path, calls: 0 }
    }

    pub(super) fn beat(&mut self) -> std::io::Result<()> {
        self.calls += 1;
        if self.calls % 64 != 1 {
            return Ok(());
        }
        let pending = self.path.with_extension("tmp");
        let marker = format!("{HEARTBEAT_MAGIC}\n{}\n", now_nanos(SystemTime::now()));
        fs::write(&pending, marker)?;
        fs::rename(&pending, &self.path)?;
        Ok(())
    }
}

/// Start the heartbeat for a freshly claimed container: the first
/// beat proves the container is writable before any walk output
/// exists. A beat failure removes the just-claimed container, so it
/// never strands a markerless directory the sweep would refuse for
/// lack of ownership proof.
pub(super) fn start_heartbeat(staging: &Path) -> Result<Heartbeat, ExportError> {
    let mut heartbeat = Heartbeat::new(staging.join(HEARTBEAT_FILE));
    heartbeat.beat().map_err(|source| {
        let _ = fs::remove_dir_all(staging);
        ExportError::Io {
            path: staging.to_path_buf(),
            source,
        }
    })?;
    Ok(heartbeat)
}
