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
use wyrd_format::{BaoRoot, ContentId, FetchStatus, MemoryObjectStore, StorageId};
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

fn view_status(parts: &TerminalParts, id: &ContentId) -> FetchStatus {
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
                    // terminal verdict completes, anything else waits.
                    let status = projection.read().unwrap().view().status(&chunk);
                    matches!(status, FetchStatus::Available | FetchStatus::Unavailable(_))
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
    // The new waiter reopens the attempt: pending, then re-admitted.
    parts.wants.register(chunk).unwrap();
    live.sync_once(&mut loaded.rig.relay, Some(&mut dead))
        .unwrap();
    assert!(
        parts.wants.is_admitted(&chunk),
        "the retry re-admits onto the durable policy"
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
