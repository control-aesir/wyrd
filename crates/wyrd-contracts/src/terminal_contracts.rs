//! Contracts 47-48: generation-scoped terminal fetch state with
//! waiter completion (`docs/peer-repair.md` Part 1, first child).
//!
//! The generation model — what goes terminal, when, and as which
//! verdict — is pinned engine-side in
//! `wyrd-sync/src/runtime/engine/tests_terminal.rs`. These contracts
//! pin the live loop's half over public APIs: terminal generations
//! complete their waiters through the real registry, retire from
//! admission, reopen on a new waiter, and heal into availability.
//! The rig publishes one snapshot over the in-memory peer; the dead
//! wrapper kills only the object routes, so manifests and bodies
//! converge while every representation fails in transport.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use wyrd_core::live::LiveConfig;
use wyrd_core::node::WyrdNode;
use wyrd_core::view::RuntimeMaterialization;
use wyrd_core::want::wait_for_materialization;
use wyrd_daemon::fuse::FuseBackend;
use wyrd_format::{
    BaoRoot, ContentId, FetchStatus, FsObjectStore, MemoryObjectStore, ObjectKind, ObjectStore,
    StorageId,
};
use wyrd_fuse::DriveView;
use wyrd_sync::bulk::{AttemptBudget, BulkError, BulkSource, MemoryBulkSource, SealedManifest};
use wyrd_sync::runtime::{EngineError, RoutePublishing, RouteReport, RuntimeState};

use crate::support::Loaded;

type TerminalNode = WyrdNode<DriveView<MemoryObjectStore, RuntimeMaterialization>>;
type TerminalLive = wyrd_core::live::LiveNode<TerminalView>;
type TerminalParts = wyrd_core::live::LiveParts<TerminalView>;
type TerminalView = DriveView<MemoryObjectStore, RuntimeMaterialization>;

/// A peer whose object routes fail in transport while manifests and
/// bodies flow: transport-root fetches die everywhere (bodies fall
/// back to their snapshot address), and the named storage
/// representations die on both routes. Killable mid-test so a
/// terminal generation can heal into the next one.
struct DeadObjects {
    inner: MemoryBulkSource,
    kill: bool,
    dead_storage: BTreeSet<StorageId>,
}

impl AttemptBudget for DeadObjects {}

impl BulkSource for DeadObjects {
    fn fetch_root_manifest(
        &mut self,
        snapshot: &wyrd_format::SnapshotId,
        max: usize,
    ) -> Result<Option<SealedManifest>, BulkError> {
        self.inner.fetch_root_manifest(snapshot, max)
    }

    fn fetch_snapshot(
        &mut self,
        snapshot: &wyrd_format::SnapshotId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        self.inner.fetch_snapshot(snapshot, max)
    }

    fn fetch_sealed(
        &mut self,
        storage: &StorageId,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.kill && self.dead_storage.contains(storage) {
            return Err(BulkError::Transport("object route dead".into()));
        }
        self.inner.fetch_sealed(storage, max)
    }

    fn fetch_transport(
        &mut self,
        root: &BaoRoot,
        max: usize,
    ) -> Result<Option<Vec<u8>>, BulkError> {
        if self.kill {
            return Err(BulkError::Transport("object route dead".into()));
        }
        self.inner.fetch_transport(root, max)
    }
}

impl RoutePublishing for DeadObjects {
    fn publish_routes(&mut self, _state: &RuntimeState) -> Result<RouteReport, EngineError> {
        Ok(RouteReport::default())
    }
}

/// One snapshot published, announced, and wanted, with every object
/// route dead: manifests and bodies converge, the chunk's
/// representations fail in transport. Returns the rig (for its relay
/// and teardown), the composed live node with its parts, the dead
/// peer, and the chunk under test.
fn terminal_setup() -> (Loaded, TerminalLive, TerminalParts, DeadObjects, ContentId) {
    let mut loaded = Loaded::new("terminal.txt", b"terminal probe");
    loaded.publish_all();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let chunk = *loaded
        .content
        .content_ids
        .iter()
        .find(|id| **id != loaded.content.tree_id)
        .expect("the fixture carries a chunk beside its tree");
    // Every object route dies except the tree's: the tree lands so
    // the head's closure verifies and the projection publishes, while
    // the chunk's representations fail in transport. (Closure gates
    // on trees, never chunks — chunks are fetched on demand.)
    let dead_storage: BTreeSet<StorageId> = loaded
        .content
        .objects
        .iter()
        .map(|(storage, _)| *storage)
        .filter(|storage| *storage != loaded.content.tree_storage)
        .collect();
    let objects = std::mem::take(&mut loaded.objects);
    let node: TerminalNode = WyrdNode::new(engine, objects).unwrap();
    let (live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let bulk = std::mem::take(&mut loaded.bulk);
    let dead = DeadObjects {
        inner: bulk,
        kill: true,
        dead_storage,
    };
    (loaded, live, parts, dead, chunk)
}

fn view_status<S: ObjectStore>(
    parts: &wyrd_core::live::LiveParts<DriveView<S, RuntimeMaterialization>>,
    id: &ContentId,
) -> FetchStatus
where
    S::Error: std::fmt::Debug,
{
    parts.projection.read().unwrap().view().status(id)
}

/// Drive passes until the chunk is terminal or the budget runs out.
fn drive_to_terminal(
    loaded: &mut Loaded,
    live: &mut TerminalLive,
    parts: &TerminalParts,
    dead: &mut DeadObjects,
    chunk: &ContentId,
) {
    let mut terminal = false;
    for _ in 0..60 {
        live.sync_once(&mut loaded.rig.relay, Some(dead)).unwrap();
        if view_status(parts, chunk) == FetchStatus::Unavailable(1) {
            terminal = true;
            break;
        }
    }
    assert!(terminal, "dead object routes complete generation 1");
}

/// Contract 47 (`terminal_generation_completes_every_waiter_of_the_identity`):
/// three waiters registered while fetching all release on terminal —
/// bounded `EIO`, never the deadline — against the real registry, and
/// the terminal identity retires from admission even with its waiters
/// outstanding.
#[test]
fn terminal_generation_completes_every_waiter_of_the_identity() {
    let (mut loaded, mut live, parts, mut dead, chunk) = terminal_setup();
    let wants = Arc::clone(&parts.wants);
    std::thread::scope(|scope| {
        let mut waiters = Vec::new();
        for _ in 0..3 {
            let wants = Arc::clone(&wants);
            let projection = Arc::clone(&parts.projection);
            waiters.push(scope.spawn(move || {
                wait_for_materialization(&wants, chunk, Duration::from_secs(20), || {
                    // The production probe's shape: success or a
                    // terminal verdict completes, anything else waits —
                    // and a terminal observation notes reopen demand,
                    // mirroring the FUSE demand path, so the waiter's
                    // retry finds a new generation.
                    let status = projection.read().unwrap().view().status(&chunk);
                    match status {
                        FetchStatus::Available => true,
                        FetchStatus::Unavailable(_) => {
                            wants.note_reopen_demand(&chunk);
                            true
                        }
                        _ => false,
                    }
                })
            }));
        }
        // The waiters registered before the terminal pass: the pass
        // admits with waiters outstanding, then completes the
        // generation under them.
        drive_to_terminal(&mut loaded, &mut live, &parts, &mut dead, &chunk);
        for waiter in waiters {
            waiter
                .join()
                .unwrap()
                .expect("terminal completes every waiter");
        }
    });
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Unavailable(1),
        "nothing healed: the verdict stood while waiters released"
    );
    // The mid-wait composition: the probes' notes reopen generation
    // 2 on the next pass, so the waiters' retries would find a fresh
    // attempt instead of the verdict they just observed.
    live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
        .unwrap();
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Fetching,
        "observed demand rotated the generation after completion"
    );
    assert!(
        !parts.wants.is_admitted(&chunk),
        "the terminal identity retired from admission with waiters outstanding"
    );
    assert!(
        parts.wants.peek_pending().is_empty(),
        "completion released every waiter"
    );
    assert_eq!(
        parts.wants.waiter_count(&chunk),
        0,
        "no leaked waiter counts"
    );
    loaded.rig.teardown();
}

/// Contract 48 (`a_new_waiter_after_terminal_starts_a_new_generation`):
/// register, drive to terminal, re-register — the identity
/// re-enters as pending, is re-admitted, and, once the routes heal,
/// the second generation fulfills verified. Negative control: the
/// terminal stands until the new waiter arrives; it is not
/// permanently terminal, and it does not heal itself.
#[test]
fn a_new_waiter_after_terminal_starts_a_new_generation() {
    let (mut loaded, mut live, parts, mut dead, chunk) = terminal_setup();
    drive_to_terminal(&mut loaded, &mut live, &parts, &mut dead, &chunk);
    assert!(
        !parts.wants.is_admitted(&chunk),
        "the terminal pass retired the identity"
    );
    // Passes without a new waiter change nothing observable: the
    // verdict stands at generation 1 past cooldown expiry and past
    // the background plan's resumed attempts — no rotation without
    // demand (a full cooldown plus a full strike cycle with nobody
    // reading).
    for _ in 0..16 {
        live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
            .unwrap();
        assert_eq!(
            view_status(&parts, &chunk),
            FetchStatus::Unavailable(1),
            "no waiter, no rotation: the verdict stands"
        );
    }
    // The new waiter reopens the attempt — mirroring exactly what
    // the FUSE demand path does on a terminal-first read: register
    // the demand, then note it for the generation sweep.
    parts.wants.register(chunk).unwrap();
    live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
        .unwrap();
    // Admitted (pending was real) but not reopened: registration
    // alone carries no generation rotation. The terminal stands and
    // the settlement sweep retires the admitted mark again — the
    // pin for note necessity below.
    assert!(
        !parts.wants.is_admitted(&chunk),
        "registration without a note retires against the standing verdict"
    );
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Unavailable(1),
        "no note, no reopen"
    );
    parts.wants.note_reopen_demand(&chunk);
    live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
        .unwrap();
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Fetching,
        "the note reopened generation 2: the verdict cleared with nothing admitted"
    );
    assert!(
        !parts.wants.is_admitted(&chunk),
        "reopen needs no admission: the durable policy already holds the demand"
    );
    // The routes heal: the new generation attempts again and lands
    // verified bytes — quarantined, re-wanted, fetched, Available.
    dead.kill = false;
    let mut available = false;
    for _ in 0..30 {
        live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
            .unwrap();
        if view_status(&parts, &chunk) == FetchStatus::Available {
            available = true;
            break;
        }
    }
    assert!(available, "the second generation fulfills once routes heal");
    loaded.rig.teardown();
}

/// Contract 52 (`quarantined_chunk_heals_from_a_live_peer_without_remount`):
/// the full repair lifecycle over public APIs with a real serving
/// peer and the real FUSE demand path — bad bytes, observed
/// verification failure, discard and unclaim, re-want, live
/// refetch, verified `Available`, and the original waiter served —
/// with no remount or restart anywhere. This is OD-12-1 and OD-12-2
/// together: removal plus repair-on-demand closing into serving.
///
/// The reader asserts the designed contract, not transparent
/// retry: the rejected first read converts into the demand flow
/// (`with_demand`), so the waiting reader heals in the same read
/// when the peer serves promptly — and fails bounded `EIO` when it
/// does not.
#[test]
fn quarantined_chunk_heals_from_a_live_peer_without_remount() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use wyrd_core::live::LiveParts;

    const BODY: &[u8] = b"healed through repair";
    let mut loaded = Loaded::new("heal.txt", BODY);
    loaded.publish_all();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let chunk = *loaded
        .content
        .content_ids
        .iter()
        .find(|id| **id != loaded.content.tree_id)
        .expect("the fixture carries a chunk beside its tree");

    // The member stores on disk: bitrot needs a real live name.
    let dir = std::env::temp_dir().join(format!(
        "wyrd-contracts-quarantine-heal-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let node: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.join("objects")).unwrap()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let LiveParts {
        projection,
        wants,
        mutations,
        open_timeout,
        budgets,
    } = &parts;
    // The fetch lands through the live peer: drive until the chunk
    // is verified local and the published generation serves the
    // path (the reader opens through the projection, not the
    // materialization status). Deadline-bounded, not
    // fixed-iteration: under gate load the same passes take
    // longer, and a pass budget must never be what fails the
    // test.
    let started = std::time::Instant::now();
    let mut available = false;
    while started.elapsed() < Duration::from_secs(120) {
        live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
            .unwrap();
        let slot = parts.projection.read().unwrap();
        if slot.view().status(&chunk) == FetchStatus::Available
            && slot.view().lookup("heal.txt").is_ok()
        {
            available = true;
            break;
        }
    }
    assert!(available, "the member fetched the chunk verified");
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Available,
        "step 7 precondition: verified bytes are local"
    );

    // Step 1: host-side surgery — the live name stops hashing back.
    // Length-identical tampering: fail-closed on content, not size.
    let hex = chunk.to_string();
    let live_name = dir
        .join("objects")
        .join("objects")
        .join(format!("{:02x}", ObjectKind::Chunk.byte()))
        .join(&hex[..2])
        .join(&hex[2..]);
    std::fs::write(&live_name, b"tampered-------------").unwrap();

    // The production demand path: the backend reports the
    // rejection and the reader waits the demand flow.
    let mut backend = FuseBackend::shared_with_wants(
        Arc::clone(projection),
        Arc::clone(wants),
        Arc::clone(mutations),
        *open_timeout,
        budgets,
    );
    backend.set_quarantine(Arc::clone(live.quarantine_queue()));
    let done = Arc::new(AtomicBool::new(false));
    let mut quarantined = 0u64;
    std::thread::scope(|scope| {
        let reader_done = Arc::clone(&done);
        let reader = scope.spawn(move || {
            let handle = backend
                .open_at("heal.txt")
                .expect("the path still resolves");
            let bytes = backend
                .read_handle(handle, 0, BODY.len() as u32)
                .expect("the waiting reader heals in the same read");
            reader_done.store(true, Ordering::SeqCst);
            bytes
        });
        // The loop repairs and refetches while the reader waits:
        // drain, unclaim, re-pend, and the live peer serves the
        // fresh generation. No restart, no remount — one engine,
        // one store, one live node throughout. Deadline-bounded
        // for the same reason as above: the reader's own 30s
        // demand deadline is what bounds the wait, and the drive
        // loop must not stop first under load.
        let started = std::time::Instant::now();
        while !done.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(120) {
            let pass = live
                .sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
                .unwrap();
            quarantined += pass.quarantined.observed;
        }
        let bytes = reader.join().expect("the reader thread joins");
        // Steps 2-8: the tampered bytes were never served (the
        // reader holds the original body, byte for byte), the
        // rejection was diagnosed, and the refetch verified.
        assert_eq!(bytes, BODY, "fail-closed: original bytes, never tampered");
        assert!(
            quarantined > 0,
            "the rejection was diagnosed through the drain"
        );
    });
    assert!(
        done.load(Ordering::SeqCst),
        "the original waiter succeeded, not a later one"
    );
    assert_eq!(
        view_status(&parts, &chunk),
        FetchStatus::Available,
        "the new representation is locally Available"
    );
    // Serving continues on the healed bytes: a fresh open reads
    // them back through the same backend and loop.
    let mut backend = FuseBackend::shared_with_wants(
        Arc::clone(projection),
        Arc::clone(wants),
        Arc::clone(mutations),
        *open_timeout,
        budgets,
    );
    backend.set_quarantine(Arc::clone(live.quarantine_queue()));
    let handle = backend.open_at("heal.txt").unwrap();
    assert_eq!(
        backend.read_handle(handle, 0, BODY.len() as u32).unwrap(),
        BODY,
        "post-heal reads serve verified bytes"
    );
    loaded.rig.teardown();
    std::fs::remove_dir_all(dir).unwrap();
}

/// Contract 53 (`scrubbed_chunk_heals_from_a_live_peer_without_a_waiter`):
/// out-of-band loss of fetched bytes heals with no reader and no
/// waiter anywhere in the picture. The member holds verified bytes
/// under a durable claim; host-side surgery deletes the live file
/// outright (the v0 loss model: bitrot fails closed on read, but a
/// vanished file never even reaches verification). The loop alone —
/// no demand, no reopen note — must observe the missing bytes,
/// clear the stale claim, and re-drive the walk through the live
/// peer back to verified `Available`, bytes back on disk.
#[test]
fn scrubbed_chunk_heals_from_a_live_peer_without_a_waiter() {
    const BODY: &[u8] = b"healed through scrub";
    let mut loaded = Loaded::new("scrub.txt", BODY);
    loaded.publish_all();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let chunk = *loaded
        .content
        .content_ids
        .iter()
        .find(|id| **id != loaded.content.tree_id)
        .expect("the fixture carries a chunk beside its tree");

    let dir = std::env::temp_dir().join(format!(
        "wyrd-contracts-scrub-heal-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let node: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.join("objects")).unwrap()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let started = std::time::Instant::now();
    let mut available = false;
    while started.elapsed() < Duration::from_secs(120) {
        live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
            .unwrap();
        let slot = parts.projection.read().unwrap();
        if slot.view().status(&chunk) == FetchStatus::Available
            && slot.view().lookup("scrub.txt").is_ok()
        {
            available = true;
            break;
        }
    }
    assert!(available, "the member fetched the chunk verified");

    // Step 1: host-side surgery — the live file simply vanishes.
    let hex = chunk.to_string();
    let live_name = dir
        .join("objects")
        .join("objects")
        .join(format!("{:02x}", ObjectKind::Chunk.byte()))
        .join(&hex[..2])
        .join(&hex[2..]);
    std::fs::remove_file(&live_name).unwrap();

    // No reader, no waiter: the loop alone must observe the loss,
    // unclaim the identity, and refetch it from the live peer.
    // Deadline-bounded like contract 52: under gate load the same
    // passes take longer, and a pass budget must never be what
    // fails the test.
    let started = std::time::Instant::now();
    let mut healed = false;
    let mut scrubbed = 0u64;
    let mut claims_cleared = 0u64;
    while started.elapsed() < Duration::from_secs(120) {
        let pass = live
            .sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
            .unwrap();
        scrubbed += pass.scrubbed.observed;
        claims_cleared += pass.scrubbed.claims_cleared;
        if view_status(&parts, &chunk) == FetchStatus::Available
            && std::fs::read(&live_name).is_ok_and(|bytes| bytes == BODY)
        {
            healed = true;
            break;
        }
    }
    assert!(
        healed,
        "out-of-band loss heals through the background plan with no waiter"
    );
    assert!(
        scrubbed > 0,
        "the loss was diagnosed through the scrub drain, not silently re-fetched"
    );
    assert_eq!(
        claims_cleared, 1,
        "exactly one stale claim cleared for one lost identity"
    );
    loaded.rig.teardown();
    std::fs::remove_dir_all(dir).unwrap();
}

/// Contract 54 (`scrubbed_append_heals_from_a_live_peer_without_remount`):
/// the peer-served half of the write-path loss claim. The member
/// holds a verified chunk under a durable claim; host-side surgery
/// deletes the live file; an appending writer then commits while
/// the loop runs against the live peer. The first evaluation finds
/// the base gone, the scrub unclaims it on the same pass, the
/// refetch heals, and the commit lands — extended content served
/// through the same mount, no remount, no restart.
#[test]
fn scrubbed_append_heals_from_a_live_peer_without_remount() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use wyrd_core::live::LiveParts;

    const BODY: &[u8] = b"append through scrub";
    const APPEND: &[u8] = b"!";
    let mut loaded = Loaded::new("extend.txt", BODY);
    loaded.publish_all();
    loaded.publish_body_and_announcement(None);
    let report = loaded.drain();
    assert_eq!(report.accepted, 2, "the capability and the announcement");
    let mut engine = loaded.rig.take_engine();
    loaded.want_all(&mut engine);
    let chunk = *loaded
        .content
        .content_ids
        .iter()
        .find(|id| **id != loaded.content.tree_id)
        .expect("the fixture carries a chunk beside its tree");

    let dir = std::env::temp_dir().join(format!(
        "wyrd-contracts-scrub-append-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let node: WyrdNode<DriveView<FsObjectStore, RuntimeMaterialization>> =
        WyrdNode::new(engine, FsObjectStore::open(dir.join("objects")).unwrap()).unwrap();
    let (mut live, parts) = node
        .into_live(Duration::from_secs(30), &LiveConfig::default())
        .unwrap();
    let started = std::time::Instant::now();
    let mut available = false;
    while started.elapsed() < Duration::from_secs(120) {
        live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
            .unwrap();
        let slot = parts.projection.read().unwrap();
        if slot.view().status(&chunk) == FetchStatus::Available
            && slot.view().lookup("extend.txt").is_ok()
        {
            available = true;
            break;
        }
    }
    assert!(available, "the member fetched the chunk verified");

    // Step 1: out-of-band loss — the live file simply vanishes.
    let hex = chunk.to_string();
    let live_name = dir
        .join("objects")
        .join("objects")
        .join(format!("{:02x}", ObjectKind::Chunk.byte()))
        .join(&hex[..2])
        .join(&hex[2..]);
    std::fs::remove_file(&live_name).unwrap();

    // Step 2: the appending writer commits while the loop pumps
    // against the live peer. The base is gone, so the first
    // evaluation defers — then the scrub unclaims, the refetch
    // heals, and the commit lands.
    let LiveParts {
        projection,
        wants,
        mutations,
        open_timeout,
        budgets,
    } = &parts;
    let mut backend = FuseBackend::shared_with_wants(
        Arc::clone(projection),
        Arc::clone(wants),
        Arc::clone(mutations),
        *open_timeout,
        budgets,
    );
    backend.set_quarantine(Arc::clone(live.quarantine_queue()));
    backend.set_scrub(Arc::clone(live.scrub_queue()));
    let done = Arc::new(AtomicBool::new(false));
    let mut committed = false;
    std::thread::scope(|scope| {
        let commit_done = Arc::clone(&done);
        let writer = scope.spawn(move || {
            let handle = backend
                .open_write("extend.txt", libc::O_WRONLY | libc::O_APPEND)
                .expect("the path still resolves");
            backend
                .write_handle(handle, 0, APPEND)
                .expect("the append buffers");
            let outcome = backend.commit_handle(handle);
            commit_done.store(true, Ordering::SeqCst);
            outcome
        });
        // The loop repairs and refetches while the commit waits:
        // unclaim on an early pass, refetch from the live peer,
        // author over the healed base. Deadline-bounded like the
        // contracts above; the commit's own prerequisite deadline
        // bounds the writer even if the loop stalls.
        let started = std::time::Instant::now();
        while !done.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(120) {
            live.sync_once(&mut loaded.rig.relay, Some(&mut loaded.bulk))
                .unwrap();
        }
        let outcome = writer.join().expect("the writer thread joins");
        assert_eq!(outcome, Ok(()), "the append lands once the refetch heals");
        committed = true;
    });
    assert!(committed, "the writer finished inside the deadline");

    // Serving continues on the extended bytes: a fresh open reads
    // the original body plus the append through the same backend.
    let backend = FuseBackend::shared_with_wants(
        Arc::clone(projection),
        Arc::clone(wants),
        Arc::clone(mutations),
        *open_timeout,
        budgets,
    );
    let handle = backend.open_at("extend.txt").unwrap();
    let mut expected = BODY.to_vec();
    expected.extend_from_slice(APPEND);
    assert_eq!(
        backend
            .read_handle(handle, 0, expected.len() as u32)
            .unwrap(),
        expected,
        "post-heal reads serve the extended bytes"
    );
    loaded.rig.teardown();
    std::fs::remove_dir_all(dir).unwrap();
}
