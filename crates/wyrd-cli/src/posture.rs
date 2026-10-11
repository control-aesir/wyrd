//! The vault posture sidecar (issue `22c`, decision B): a disposable,
//! non-authoritative projection of what the running vault process knows,
//! readable without opening the exclusive durable store.
//!
//! The contract, in one place:
//!
//! - Location: `<drive_dir>/vault.posture`, next to `mailbox.seen` — a
//!   deterministic per-drive path whose read never acquires the store
//!   lock (the lock guards the store open, not the directory).
//! - Contents: process posture only — instance identity, serving id,
//!   startup/ready timestamps, last-pass timestamp and verdict, run
//!   counters, posture timestamp. No content ids, no secrets, no device
//!   identifiers. The process section of `vault status` reveals nothing
//!   the ready/posture log lines do not already carry.
//! - Freshness: every read classifies the file fresh or stale against
//!   [`POSTURE_FRESHNESS`] and exposes the posture timestamp. A stale
//!   file is the last recorded state, never aliveness — and a fresh
//!   file is not aliveness either, only recency: a process can die
//!   immediately after writing. Status always reports liveness
//!   unverified.
//! - Authority: the sidecar is never authoritative for convergence,
//!   membership, quota, or durable content. Durable queries stay under
//!   the flock; when the vault runs, they report unavailable instead.
//! - Lifecycle: atomic, fsync'd publish (temp write, file sync,
//!   rename, directory sync, so a power loss lands the previous
//!   generation or nothing); instance-scoped (a fresh random id per
//!   process, written only after this process claims the lock, so a
//!   restart can never inherit the previous instance's ready state);
//!   best-effort (a failed write warns to the log and never fails the
//!   vault).
//! - Privacy: the reader parses a fixed schema and ignores unknown
//!   fields, so a future field can never smuggle a prohibited
//!   identifier into the rendered output.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use wyrd_daemon::vault::POSTURE_INTERVAL;

/// File name of the posture sidecar inside the drive directory.
pub(crate) const POSTURE_FILENAME: &str = "vault.posture";

/// Schema version the reader accepts. A version bump means the old
/// reader reports the file malformed (safe: unavailable, never a
/// false claim), never a best-effort reinterpretation.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// How old a posture may be before it reads stale: three posture
/// intervals, so one missed write (a wedged loop, a slow pass) does
/// not flip a live vault to stale, while a dead process goes stale
/// promptly. Explicit and documented (`docs/cli.md`): the threshold
/// is part of the status contract, not a tuning knob.
pub(crate) const POSTURE_FRESHNESS: Duration = Duration::from_secs(POSTURE_INTERVAL.as_secs() * 3);

// The threshold is a whole-seconds multiple of a whole-seconds
// interval today; if the interval ever goes sub-second this fails
// the build instead of silently installing a 0s threshold that
// marks every posture stale on arrival.
const _: () = assert!(
    POSTURE_FRESHNESS.as_secs() > 0,
    "freshness threshold must stay positive"
);

/// Deterministic per-drive sidecar path. Reading it opens no store
/// and takes no lock.
pub(crate) fn sidecar_path(drive_dir: &Path) -> PathBuf {
    drive_dir.join(POSTURE_FILENAME)
}

/// Seconds since the Unix epoch. Wall clock, not `Instant`: the file
/// crosses processes, so a monotonic per-process clock cannot serve.
pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// What the last observed pass did: it completed, or it failed with a
/// categorical class. `ok` means the pass ran clean — not that the
/// drive converged. Convergence is a durable fact; the sidecar never
/// claims it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PassVerdict {
    Ok,
    Failed,
}

/// The exact bytes on disk. Every field required: a file missing one
/// is malformed, not partially trusted. Unknown fields are ignored by
/// construction (serde's default), so schema evolution cannot widen
/// what the renderer prints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PostureFile {
    schema: u32,
    /// Fresh 128-bit hex id per process (see [`PostureRecorder`]).
    instance: String,
    /// The serving id peers dial, as the ready line prints it.
    serving_id: String,
    /// When this process claimed the drive (post-lock).
    started_unix: u64,
    /// When this process emitted ready (`None` until it does).
    ready_unix: Option<u64>,
    /// When the last pass completed or failed (`None` before the
    /// first pass outcome).
    last_pass_unix: Option<u64>,
    last_pass_verdict: Option<PassVerdict>,
    /// Categorical failure class (`Some` only when the verdict is
    /// failed): bare class names, never error text or identities.
    last_pass_class: Option<String>,
    last_pass_consecutive: Option<u32>,
    passes: u64,
    errors: u64,
    sent: u64,
    uptime_secs: u64,
    /// When this file was written.
    posture_unix: u64,
}

/// Publishes one process's posture. The host owns the recorder the
/// way it owns stderr: the composer reports facts through
/// [`VaultEvent`](wyrd_daemon::vault::VaultEvent), the recorder turns
/// the ready/posture/failure facts into sidecar generations. Every
/// publish is best-effort — the vault never fails for its status
/// surface.
pub(crate) struct PostureRecorder {
    path: PathBuf,
    tmp: PathBuf,
    instance: String,
    state: Mutex<RecorderState>,
}

struct RecorderState {
    serving_id: String,
    started_unix: u64,
    ready_unix: Option<u64>,
    last_pass_unix: Option<u64>,
    last_pass_verdict: Option<PassVerdict>,
    last_pass_class: Option<String>,
    last_pass_consecutive: Option<u32>,
    passes: u64,
    errors: u64,
    sent: u64,
    uptime_secs: u64,
}

impl PostureRecorder {
    /// Claim the sidecar for a new process instance. The id is fresh
    /// randomness per call — never derived from the drive, so a
    /// restart cannot collide with the instance it replaces. Fails
    /// openly when the platform yields no entropy: a vault that
    /// cannot mint an instance id must not start borrowing the
    /// previous instance's posture.
    pub(crate) fn new(drive_dir: &Path, serving_id: String) -> io::Result<Self> {
        let mut id = [0u8; 16];
        // getrandom 0.2's error carries no std impl, so the mapping
        // names the failure statically: entropy is either available
        // or the platform is broken, and the detail adds nothing.
        getrandom::getrandom(&mut id)
            .map_err(|_| io::Error::other("platform entropy unavailable"))?;
        let path = sidecar_path(drive_dir);
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        Ok(PostureRecorder {
            path,
            tmp: PathBuf::from(tmp),
            instance: hex::encode(id),
            state: Mutex::new(RecorderState {
                serving_id,
                started_unix: now_unix(),
                ready_unix: None,
                last_pass_unix: None,
                last_pass_verdict: None,
                last_pass_class: None,
                last_pass_consecutive: None,
                passes: 0,
                errors: 0,
                sent: 0,
                uptime_secs: 0,
            }),
        })
    }

    /// First write, immediately after the lock is claimed: the new
    /// instance announces itself as starting, never ready. Writing
    /// here (not before the lock) is what keeps a lock-refused
    /// starter from clobbering the winner's posture; writing at all
    /// (not waiting for ready) is what keeps a crash-then-restart
    /// from leaving the dead instance's file looking current.
    pub(crate) fn note_startup(&self) {
        self.publish();
    }

    /// This process emitted ready: record it under this instance only.
    pub(crate) fn note_ready(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.ready_unix = Some(now_unix());
        }
        self.publish();
    }

    /// One pass completed: counters advance and the last-pass verdict
    /// is `ok` — the pass ran clean, which says nothing about
    /// convergence (see [`PassVerdict`]).
    pub(crate) fn note_posture(&self, passes: u64, errors: u64, sent: u64, uptime_secs: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.passes = passes;
            state.errors = errors;
            state.sent = sent;
            state.uptime_secs = uptime_secs;
            state.last_pass_unix = Some(now_unix());
            state.last_pass_verdict = Some(PassVerdict::Ok);
            state.last_pass_class = None;
            state.last_pass_consecutive = None;
        }
        self.publish();
    }

    /// One pass failed: the verdict turns with its class and streak.
    /// A pre-ready failure still publishes — under the new instance
    /// with `ready: none`, which is the truth (starting and failing),
    /// not an inherited readiness.
    pub(crate) fn note_failure(&self, class: String, consecutive: u32) {
        if let Ok(mut state) = self.state.lock() {
            state.last_pass_unix = Some(now_unix());
            state.last_pass_verdict = Some(PassVerdict::Failed);
            state.last_pass_class = Some(class);
            state.last_pass_consecutive = Some(consecutive);
        }
        self.publish();
    }

    /// One atomic, durable generation: serialize under the lock,
    /// write the temp file, fsync the file, rename over the sidecar,
    /// fsync the directory. A crash or power loss lands either the
    /// previous generation (rename never reached the journal) or an
    /// ignored temp file — never a torn read, which is why the
    /// reader trusts any complete file it finds. Lock poisoning (a
    /// panicking holder) publishes nothing rather than a half-updated
    /// file. Bounded by construction: fixed schema, fixed-length
    /// ids, verdict class from a finite enum — no pass-through text
    /// ever reaches the file.
    fn publish(&self) {
        let bytes = match self.state.lock() {
            Ok(state) => serde_json::to_vec_pretty(&PostureFile {
                schema: SCHEMA_VERSION,
                instance: self.instance.clone(),
                serving_id: state.serving_id.clone(),
                started_unix: state.started_unix,
                ready_unix: state.ready_unix,
                last_pass_unix: state.last_pass_unix,
                last_pass_verdict: state.last_pass_verdict,
                last_pass_class: state.last_pass_class.clone(),
                last_pass_consecutive: state.last_pass_consecutive,
                passes: state.passes,
                errors: state.errors,
                sent: state.sent,
                uptime_secs: state.uptime_secs,
                posture_unix: now_unix(),
            }),
            Err(_) => return,
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(_) => return,
        };
        // Best-effort by contract: the status surface must never fail
        // the vault. One throttled-by-cadence warning (publishes only
        // happen on loop events) keeps the failure visible without
        // spamming the supervisor's capture.
        let durable = (|| -> io::Result<()> {
            let mut tmp = fs::File::create(&self.tmp)?;
            io::Write::write_all(&mut tmp, &bytes)?;
            tmp.sync_all()?;
            drop(tmp);
            fs::rename(&self.tmp, &self.path)?;
            if let Some(parent) = self.path.parent() {
                fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })();
        if durable.is_err() {
            tracing::warn!(
                stage = "posture",
                "posture sidecar publish failed; continuing without it"
            );
        }
    }
}

/// What the sidecar read means. Fresh and stale both carry the parsed
/// file; absent and malformed carry no facts at all — the renderer
/// must not upgrade either into a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessPosture {
    /// Posture within [`POSTURE_FRESHNESS`]: recent, still not proof
    /// of aliveness.
    Fresh(PostureFile),
    /// Posture beyond the threshold with its age: the last recorded
    /// state, explicitly not evidence the process is alive.
    Stale(PostureFile, u64),
    /// No sidecar: the vault never reached a publish, or the file was
    /// removed. Not evidence of anything.
    Absent,
    /// Present but not schema v1 (bad JSON, wrong version, missing
    /// field, non-hex instance): treated as absent, never as healthy.
    Malformed,
}

/// Read and classify the sidecar. Opens only the sidecar path — never
/// the store, never the lock — so a running vault's exclusivity is
/// undisturbed by the query.
pub(crate) fn read_posture(path: &Path) -> ProcessPosture {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ProcessPosture::Absent,
        Err(_) => return ProcessPosture::Malformed,
    };
    let file: PostureFile = match serde_json::from_slice(&bytes) {
        Ok(file) => file,
        Err(_) => return ProcessPosture::Malformed,
    };
    if file.schema != SCHEMA_VERSION
        || file.instance.len() != 32
        || file.instance.bytes().any(|byte| !byte.is_ascii_hexdigit())
        || file.serving_id.is_empty()
    {
        return ProcessPosture::Malformed;
    }
    let age = now_unix().saturating_sub(file.posture_unix);
    if age <= POSTURE_FRESHNESS.as_secs() {
        ProcessPosture::Fresh(file)
    } else {
        ProcessPosture::Stale(file, age)
    }
}

/// Render the process section: flat `process:` lines, greppable and
/// strictly process facts. The liveness disclaimer is unconditional —
/// even a fresh posture only proves recency. `proven_free` is true
/// exactly when the durable probe already opened the store, which
/// proves no process holds the lock: a timestamp-fresh file is then
/// retained history, and the header says so instead of agreeing with
/// a durable section that shows a stopped drive.
pub(crate) fn render_process_section(posture: &ProcessPosture, proven_free: bool) -> String {
    fn age_line(posture_unix: u64) -> String {
        let age = now_unix().saturating_sub(posture_unix);
        format!("{posture_unix} ({age}s ago)")
    }
    let mut out = String::new();
    match posture {
        ProcessPosture::Fresh(file) => {
            if proven_free {
                out.push_str(&format!(
                    "process: retained posture {} (threshold {}s; drive not held by any process: last recorded state, not a live process; liveness unverified)\n",
                    age_line(file.posture_unix),
                    POSTURE_FRESHNESS.as_secs()
                ));
            } else {
                out.push_str(&format!(
                    "process: fresh posture {} (threshold {}s; liveness unverified)\n",
                    age_line(file.posture_unix),
                    POSTURE_FRESHNESS.as_secs()
                ));
            }
            render_posture_facts(&mut out, file);
        }
        ProcessPosture::Stale(file, _) => {
            out.push_str(&format!(
                "process: STALE posture {} (beyond {}s threshold: last recorded state, not evidence the process is alive; liveness unverified)\n",
                age_line(file.posture_unix),
                POSTURE_FRESHNESS.as_secs()
            ));
            render_posture_facts(&mut out, file);
        }
        ProcessPosture::Absent => {
            out.push_str(
                "process: no posture recorded (vault never published, or sidecar removed)\n",
            );
            out.push_str("process: liveness: unverified (nothing recorded to verify)\n");
        }
        ProcessPosture::Malformed => {
            out.push_str("process: posture unreadable (sidecar present but not schema v1: treating as absent, not as healthy)\n");
            out.push_str("process: liveness: unverified (nothing readable to verify)\n");
        }
    }
    out
}

/// The facts every fresh or stale file carries. Counts and
/// timestamps only — the same surface the ready/posture log lines
/// already print, so status reveals nothing log-reading does not.
/// Deliberately no source path: the operator passed the drive
/// directory, the file name is fixed, and the status surface never
/// prints filesystem paths (`docs/cli.md`).
fn render_posture_facts(out: &mut String, file: &PostureFile) {
    out.push_str(&format!("process: instance: {}\n", file.instance));
    out.push_str(&format!("process: serving: {}\n", file.serving_id));
    out.push_str(&format!("process: started: {}\n", file.started_unix));
    match file.ready_unix {
        Some(ready) => out.push_str(&format!("process: ready: {ready}\n")),
        None => out.push_str("process: ready: not yet (no ready line from this instance)\n"),
    }
    match (file.last_pass_unix, file.last_pass_verdict) {
        (Some(at), Some(PassVerdict::Ok)) => {
            out.push_str(&format!(
                "process: last pass: ok at {at} (pass ran clean; not a convergence claim)\n"
            ));
        }
        (Some(at), Some(PassVerdict::Failed)) => {
            let class = file.last_pass_class.as_deref().unwrap_or("unknown");
            let streak = file.last_pass_consecutive.unwrap_or(1);
            out.push_str(&format!(
                "process: last pass: failed ({class} class, {streak} consecutive) at {at}\n"
            ));
        }
        _ => out.push_str("process: last pass: none observed by this instance\n"),
    }
    out.push_str(&format!(
        "process: passes: {}, errors: {} retried, sends: {}, uptime: {}s\n",
        file.passes, file.errors, file.sent, file.uptime_secs
    ));
    // Unconditional, even when fresh: recency is not aliveness (see
    // the module contract). A dedicated line so the disclaimer is
    // greppable, not buried in the header prose.
    out.push_str(
        "process: liveness: unverified (a timestamp alone cannot prove the process is alive)\n",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_harness::TempDir;

    fn sidecar(dir: &TempDir) -> PathBuf {
        sidecar_path(&dir.0)
    }

    fn read_json(dir: &TempDir) -> serde_json::Value {
        let bytes = fs::read(sidecar(dir)).expect("sidecar must exist");
        serde_json::from_slice(&bytes).expect("sidecar must be JSON")
    }

    /// Forge a sidecar with explicit timestamps: the stale/future
    /// transitions are time logic, and sleeping through a 180s
    /// threshold would test patience, not code.
    fn forge(dir: &TempDir, posture_unix: u64, extra: serde_json::Value) {
        let mut file = serde_json::json!({
            "schema": 1,
            "instance": "0123456789abcdef0123456789abcdef",
            "serving_id": "aa",
            "started_unix": posture_unix - 10,
            "ready_unix": posture_unix - 5,
            "last_pass_unix": posture_unix,
            "last_pass_verdict": "ok",
            "last_pass_class": null,
            "last_pass_consecutive": null,
            "passes": 41,
            "errors": 0,
            "sent": 7,
            "uptime_secs": 312,
            "posture_unix": posture_unix,
        });
        if let (Some(map), Some(patch)) = (file.as_object_mut(), extra.as_object()) {
            for (key, value) in patch {
                map.insert(key.clone(), value.clone());
            }
        }
        fs::write(sidecar(dir), serde_json::to_vec(&file).unwrap()).unwrap();
    }

    #[test]
    fn startup_then_ready_publishes_instance_scoped_posture() {
        let dir = TempDir::new();
        let recorder = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        recorder.note_startup();
        let starting = read_json(&dir);
        assert_eq!(starting["schema"], 1);
        assert_eq!(starting["ready_unix"], serde_json::Value::Null);
        let instance = starting["instance"].as_str().unwrap().to_owned();
        assert_eq!(instance.len(), 32, "instance must be 128-bit hex");
        recorder.note_ready();
        recorder.note_posture(41, 0, 7, 312);
        let ready = read_json(&dir);
        assert_eq!(ready["instance"], instance.as_str());
        assert!(ready["ready_unix"].as_u64().unwrap() > 0);
        assert_eq!(ready["last_pass_verdict"], "ok");
        assert!(matches!(
            read_posture(&sidecar(&dir)),
            ProcessPosture::Fresh(_)
        ));
    }

    #[test]
    fn instances_differ_per_process() {
        let dir = TempDir::new();
        let first = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        first.note_startup();
        let a = read_json(&dir)["instance"].as_str().unwrap().to_owned();
        let second = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        second.note_startup();
        let b = read_json(&dir)["instance"].as_str().unwrap().to_owned();
        assert_ne!(a, b, "a restart must mint a new instance id");
    }

    #[test]
    fn restart_cannot_inherit_readiness() {
        let dir = TempDir::new();
        let dead = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        dead.note_startup();
        dead.note_ready();
        dead.note_posture(41, 0, 7, 312);
        let dead_instance = read_json(&dir)["instance"].as_str().unwrap().to_owned();
        let replacement = PostureRecorder::new(&dir.0, "bb".into()).unwrap();
        // The replacement announces itself starting before it is
        // ready: the dead instance's readiness dies with it.
        replacement.note_startup();
        let file = read_json(&dir);
        assert_ne!(
            file["instance"].as_str().unwrap(),
            dead_instance,
            "the new instance must not reuse the dead one's identity"
        );
        assert_eq!(file["ready_unix"], serde_json::Value::Null);
        assert_eq!(file["serving_id"], "bb");
        match read_posture(&sidecar(&dir)) {
            ProcessPosture::Fresh(view) => {
                assert!(view.ready_unix.is_none(), "fresh file, unready instance");
            }
            other => panic!("expected a fresh unready posture, got: {other:?}"),
        }
    }

    #[test]
    fn stale_after_threshold() {
        let dir = TempDir::new();
        let threshold = POSTURE_FRESHNESS.as_secs();
        forge(
            &dir,
            now_unix().saturating_sub(threshold),
            serde_json::json!({}),
        );
        assert!(matches!(
            read_posture(&sidecar(&dir)),
            ProcessPosture::Fresh(_)
        ));
        forge(
            &dir,
            now_unix().saturating_sub(threshold + 1),
            serde_json::json!({}),
        );
        match read_posture(&sidecar(&dir)) {
            ProcessPosture::Stale(_, age) => assert!(age > threshold),
            other => panic!("expected stale past the threshold, got: {other:?}"),
        }
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("STALE"),
            "staleness must be unmissable:\n{rendered}"
        );
        assert!(
            rendered.contains("not evidence the process is alive"),
            "stale is last-recorded, never aliveness:\n{rendered}"
        );
    }

    #[test]
    fn proven_free_renders_fresh_as_retained_history() {
        // Finding 3's pin: the same timestamp-fresh file reads as a
        // live-process posture while the drive may be held and as
        // retained history once the open proved it free. The two
        // readings must never agree with a stopped drive.
        let dir = TempDir::new();
        let recorder = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        recorder.note_startup();
        recorder.note_ready();
        recorder.note_posture(41, 0, 7, 312);
        let held = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            held.contains("process: fresh posture"),
            "held drive keeps the live reading:\n{held}"
        );
        let free = render_process_section(&read_posture(&sidecar(&dir)), true);
        assert!(
            free.contains("process: retained posture"),
            "proven-free drive reclassifies:\n{free}"
        );
        assert!(
            !free.contains("process: fresh posture"),
            "no live-process claim beside a stopped drive:\n{free}"
        );
        assert!(
            free.contains("not a live process"),
            "the retained header disclaims aliveness:\n{free}"
        );
    }

    #[test]
    fn future_posture_saturates_instead_of_wrapping() {
        let dir = TempDir::new();
        forge(&dir, now_unix() + 3600, serde_json::json!({}));
        match read_posture(&sidecar(&dir)) {
            ProcessPosture::Fresh(view) => assert_eq!(view.posture_unix, now_unix() + 3600),
            other => panic!("clock skew must not wrap the age math, got: {other:?}"),
        }
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("0s ago"),
            "skewed age saturates at zero:\n{rendered}"
        );
    }

    #[test]
    fn absent_and_malformed_fail_safe() {
        let dir = TempDir::new();
        assert_eq!(read_posture(&sidecar(&dir)), ProcessPosture::Absent);
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("no posture recorded"),
            "absence is a fact, not a verdict:\n{rendered}"
        );
        for bad in [
            b"not json at all".as_slice(),
            br#"{"schema": 2}"#,
            br#"{"schema": 1}"#,
            br#"{"schema": 1, "instance": "short", "serving_id": "aa"}"#,
            br#"{"schema": 1, "instance": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "serving_id": "aa"}"#,
            br#"{"schema": 1, "instance": "0123456789abcdef0123456789abcdef", "serving_id": ""}"#,
        ] {
            fs::write(sidecar(&dir), bad).unwrap();
            assert_eq!(
                read_posture(&sidecar(&dir)),
                ProcessPosture::Malformed,
                "must fail safe: {bad:?}"
            );
        }
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("not as healthy"),
            "malformed must never read healthy:\n{rendered}"
        );
        assert!(
            !rendered.contains("instance:"),
            "malformed carries no facts:\n{rendered}"
        );
    }

    #[test]
    fn unknown_fields_never_reach_output() {
        // The privacy pin: a future (or hostile) writer adding
        // sensitive fields must not widen what status prints. The
        // reader ignores what it does not know; the renderer prints
        // only the fixed schema.
        let dir = TempDir::new();
        forge(
            &dir,
            now_unix(),
            serde_json::json!({
                "device_secret": "hunter2-hunter2-hunter2-hunter2",
                "content_id": "b3deadbeefb3deadbeefb3deadbeefb3deadbeefb3deadbeefb3deadbeefb3de",
                "retention_promise": "everything forever",
            }),
        );
        assert!(matches!(
            read_posture(&sidecar(&dir)),
            ProcessPosture::Fresh(_)
        ));
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        for leaked in ["hunter2", "deadbeef", "retention_promise"] {
            assert!(
                !rendered.contains(leaked),
                "prohibited field reached output: {leaked}\n{rendered}"
            );
        }
    }

    #[test]
    fn failure_verdict_renders_class_never_error_text() {
        let dir = TempDir::new();
        let recorder = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        recorder.note_startup();
        recorder.note_ready();
        recorder.note_failure("Mailbox".into(), 3);
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("failed (Mailbox class, 3 consecutive)"),
            "verdict names the class and streak:\n{rendered}"
        );
    }

    #[test]
    fn fresh_posture_disclaims_liveness_and_convergence() {
        let dir = TempDir::new();
        let recorder = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        recorder.note_startup();
        recorder.note_ready();
        recorder.note_posture(41, 0, 7, 312);
        let rendered = render_process_section(&read_posture(&sidecar(&dir)), false);
        assert!(
            rendered.contains("liveness unverified"),
            "even fresh is recency, not aliveness:\n{rendered}"
        );
        assert!(
            rendered.contains("process: liveness: unverified (a timestamp alone cannot prove the process is alive)"),
            "the disclaimer is a dedicated greppable line:\n{rendered}"
        );
        assert!(
            rendered.contains("not a convergence claim"),
            "ok is a clean pass, not convergence:\n{rendered}"
        );
    }

    #[test]
    fn stray_tmp_never_poisons_reads() {
        let dir = TempDir::new();
        let recorder = PostureRecorder::new(&dir.0, "aa".into()).unwrap();
        recorder.note_startup();
        // A crashed publish leaves its temp behind; the next publish
        // overwrites it, and no read ever consults it.
        let mut tmp = sidecar(&dir).as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(PathBuf::from(tmp), b"torn bytes").unwrap();
        recorder.note_ready();
        assert!(matches!(
            read_posture(&sidecar(&dir)),
            ProcessPosture::Fresh(_)
        ));
    }

    #[test]
    fn freshness_threshold_is_three_posture_intervals() {
        assert_eq!(POSTURE_FRESHNESS, POSTURE_INTERVAL * 3);
    }
}
