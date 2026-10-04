# Fetch-on-Open

Normative design for demand-driven fetch: the daemon serving its
objects over iroh, peers announcing how to reach them, and the live
mount blocking on `open()` until the bytes it needs arrive. One
vertical feature (announcement schema, serving, demand registry,
driver, CLI composition land together in `pr/daemon-fetch-on-open`,
tracking issue `nostr:nevent1qqsfmctguvn9g9l4dtcy235fypty6k66wr3m2tjugnyzmffc9s0z9nspz9mhxue69uhkwunpwdczuap49eehg3l23hj`).

The architecture is **demand-driven**: the sync loop is not a
prefetcher. Bytes move because a filesystem consumer is waiting on
them, materialization policy (`Cached`/`Pinned`) remains the only
eager lever, and there is exactly one synchronization authority — the
engine, driven by the daemon loop.

```text
                 ┌──────────────────────────────┐
                 │  Snapshot announcement       │
                 │  (sealed, authenticated)     │
                 │  SnapshotId · epoch · node_addr │
                 └──────────────┬───────────────┘
                                │  candidate peer (untrusted)
                                ▼
                 ┌──────────────────────────────┐
                 │  IrohBulkSource (client)     │
                 │  connect · size cap · Bao    │
                 └──────────────┬───────────────┘
                                ▼
                          verified store insert
                                │
                                ▼
        materialization fact → DriveView publish
                                ▲
                                │
FUSE open/read ── WantRegistry ─► LiveNode loop ─► engine plan
      (waiter)     (wakeup channel)
```

Terminology is fixed: the protocol field is **`node_addr`** and carries
iroh's `NodeAddr` representation. The word *endpoint* is reserved for
the transport implementation (`EndpointAddr` is iroh-internal). IDs
never collide: `ContentId ≠ StorageId ≠ NodeAddr`, and nothing is ever
derived from an address.

## Peer addressing

The snapshot announcement gains the sender's current **`node_addr`**
(routing metadata inside the authenticated sealed plaintext — same
envelope, same signature, no sidecar channel). What an announcement
then means:

> This peer claims to have the material for snapshot S, and here is
> where you may attempt to retrieve it.

Rules, all decided:

1. **Routing metadata, not identity.** Nothing is derived from a
   `NodeAddr`. NodeAddr failure never invalidates the advertised
   content — a dead address is simply a stale advertisement, and the
   snapshot does not change.
2. **Authenticated association.** `node_addr` rides inside the
   announcement's sealed plaintext — never alongside it. An
   unauthenticated address would be a redirection surface even
   against unforgeable announcements.
3. **Untrusted infrastructure.** The announcement proves only
   *peer → node_addr* association. A peer's node may lie, vanish, or
   serve garbage; Bao verification and content hashing reject all of
   it before `insert_verified`. Zero-trust storage is unchanged.
4. **Freshness is not validity.** Multiple authentic announcements may
   carry different addresses for the same peer across history. There
   is no cryptographic invalidation of an older announcement by a
   newer one — announcement history stays append-only; the
   operational layer prefers the newest address and falls back on
   failure (retry, alternate peer, reannouncement).
5. **Replaceable, not durable.** Announcements are mutable routing
   advertisements; snapshots stay immutable. Address fields never
   enter `Snapshot` or any content-addressed object — an address
   change must never look like a snapshot change.
6. **Wyrd invents no address format.** The announcement carries iroh's
   `NodeAddr`; relay fallback and address selection remain iroh's
   responsibility.
7. Content verification remains the only admission control: a
   transfer counts if and only if it proves the advertised identity.

## Serving authorization (v0 posture, normative in `trust.md` T17)

Authorization = membership; object admission = content verification;
there are **no per-object ACLs in v0**. Consequence, stated
deliberately: a member who can name a `StorageId` can request its
ciphertext from any serving member. This is an object
availability/enumeration property, not a confidentiality breach — a
member already holds the epoch material that makes the ciphertext
meaningful. The serve surface is **object-oriented, not
filesystem-oriented**:

- answer: "can I prove this `StorageId` exists in my local store?" →
  stream its ciphertext;
- never: "can I read this filesystem path?";
- serving never exposes keys or plaintext, and never serves anything
  outside the content-addressed object space. An arbitrary file in
  the drive directory is not servable. The one plaintext exception is
  the signed snapshot body: authors serve it by `body_root` so peers
  can verify announcements against live content, and its root travels
  inside the same sealed announcements. It carries paths and
  `ContentId`s but no keys, and like everything else served it is
  content-verified, never rewritten.

The iroh-blobs serving `Router` lives in `wyrd-sync`'s transport layer
(`serving::ServingEndpoint`), beside its client half
(`bulk::IrohBulkSource`): both halves are the same iroh transport seam,
and co-locating them keeps a single implementation of endpoint, store,
and address handling that the contract suite exercises. The node
creates the endpoint (`WyrdNode::open_serving` in `wyrd-core`) and the
live loop drives it; the composer owns its lifecycle, so a different
composer can choose lifecycle without reimplementing transport. The engine itself
never learns iroh exists: route interpretation consumes the engine's
plain-data `RuntimeState` in the transport layer
(`transport::publish_recorded_routes`), and no engine API names an iroh
type.

## The WantRegistry: demand is state, the channel is just a wakeup

The registry is the primary abstraction; a channel is merely the
daemon-loop wakeup signal. The registry owns the semantic state,
and the decided properties below cover the whole demand-to-fetch
path including per-pass provider scheduling (property 8 lives in
the bulk source, not the registry, but is decided here with the
demand policy it serves):

```text
WantRegistry
  ├── pending identities   (demanded, not yet in flight)
  ├── in-flight identities (fetch admitted by the engine)
  └── waiters by identity  (FUSE openers waiting for completion)
```

```text
FUSE open/read
  │ register Want{ identity, deadline }
  ▼
  ├── identity already local        → immediate success
  ├── identity in flight            → attach waiter
  └── identity absent               → mark pending + attach waiter
                                       │
                                       ▼
                                 wake daemon loop
```

```text
daemon loop
  │ drain registry pending wants
  ▼
engine expands demand (Merkle chain: snapshot → dir trees →
file tree → chunk objects) and fetches
  ▼
complete(identity) → wake all waiters of that identity
```

Decided properties:

1. **Single authority.** FUSE never calls the engine, bulk source, or
   store; it registers demand and waits. The engine remains the only
   synchronizer.
2. **Registration is an obligation.** Registering a want either
   attaches to an existing pending/in-flight identity, creates a
   tracked pending entry, or fails. A demand is never dropped
   silently — the pre-alpha mailbox lesson, not repeated here.
3. **Bounded admission.** The registry holds at most
   `max_pending_wants` distinct identities (default 4096). A
   registration beyond the bound fails and the caller gets `EIO`
   (same POSIX surface as a timeout; distinguished in daemon
   diagnostics only). Identical outstanding wants coalesce: N
   registrations for identity X produce one in-flight
   materialization and N waiter wakeups on success or terminal
   failure. Admission itself is paced per pass
   (`max_admit_per_pass`); all bounds are normative in
   `resource-limits.md`.
4. **The channel may lose wakeups; the registry may not lose wants.**
   The loop drains the registry every pass regardless of the channel,
   so a dropped wakeup costs latency, never demand. Losing the
   channel is not losing the work.
5. **Delivery, deduplication, completion are distinct.** Delivery:
   the daemon observed the demand (registry entry exists). Dedup:
   identical outstanding identities collapse to one in-flight
   operation. Completion: every waiter for the identity is notified
   on success or terminal failure. A retrying FUSE caller may
   legitimately re-register; that is delivery again, not a second
   fetch.
6. **Timeout cancels the wait, not the fetch.** A waiter that expires
   is removed and returns `EIO`; an in-flight materialization for
   that identity continues and, on success, is published and cached.
   A slow first open therefore makes the next one instantaneous.
   Cancellation of the transfer itself, if ever built, is an
   optimization layered on this base — never part of correctness.
7. **`Fetching` is a projection, not a second state machine.** The
   registry (pending/in-flight) and engine materialization state are
   the truth; the daemon merges them at publish and the view exposes
   the result. FUSE never mutates materialization state, so
   "FUSE says Fetching while engine says Cached" cannot arise.
 8. **Each pass attempts every eligible provider the walk reaches.**
    A
   representation may name several providers (a dead route beside a
   live one after a serving restart). Under a pass budget each
   remaining candidate gets a fair share of the time left, floored so
   an early slow-but-live candidate gets a usable attempt. No
   candidate takes more than half of what's left, so a dead-first
   provider cannot spend the whole slice — but tails shrink
   geometrically, so with several hanging candidates ahead a late
   live route can get an unusably small slice, and a spent walk
   leaves the remaining candidates unattempted until the next pass.
   Candidate lists are
   short in practice (bounded by the distinct recorded providers for
   one address), so the walk reaches the live route. Two bounds
   apply: a cooled representation is not attempted at all, so a
   re-announced route is fetched once its cooldown lapses, not
   necessarily in the pass that learns it; and only subdivided
   attempts expire as deadlines — counted, and repeated nonzero
   slices back the representation off on the separate burn ledger —
   while a full-share attempt (the only or last candidate, or any
   single-route fetch outside a walk, which is the production case)
   expires as a transport failure exactly as before, so a hanging
   route with no one behind it still backs off. A zero-grant
   deadline (the walk stopped before attempting) counts — when it
   is the representation's whole story; a fallback zero grant
   masked by a primary outcome is not counted — but never backs
   off: a provider never asked carries no evidence.

## What open() materializes vs what read() demands

Wyrd is a Merkle system: resolving a path needs the manifest chain
(snapshot → directory trees → file tree); reading bytes needs the
chunk objects the file tree names. The two have different sizes and
different failure profiles, so v0 splits them explicitly:

- **`open()` materializes the manifest chain** for the resolved path
  and captures the snapshot-stable file handle (chunk identity list).
  Manifests are bounded and small; this is the part that must exist
  before an FD exists. A chain the daemon cannot fully materialize
  within the deadline fails the open with `EIO`.
- **`read()` demands chunk objects on first touch** through the same
  want path, with the same bounded blocking and `EIO` on timeout.
  Once a chunk is materialized it is cached; a sequential reader pays
  demand latency once per chunk.

Full-file-at-open (materializing every chunk before returning the FD)
is **rejected**: it makes open latency proportional to file size and
turns one flaky chunk into total open failure. The cost of the split
is accepted explicitly: **network availability is an `open()` concern
for metadata and a `read()` concern for chunks** — the strict "reads
never touch the network after open" invariant is traded away for
unbounded-open-latency avoidance. What is *not* traded away:

- the FD pins the file's content identity at open;
- `read()` never re-resolves paths or re-decides versions;
- a read blocks only on chunks of that pinned identity, and serves
  only verified local bytes;
- the common path after a warmed open is entirely local.

The filesystem-visible contract stays one sentence: **"make this path
readable within the deadline"** — never "fetch object X"; the
materialization layer decides whether that means one object or twenty,
and FUSE never knows. Resolution against the projected namespace is
not demand: a path no installed head contains is `ENOENT` immediately —
open blocks for content *after* announce, never for announcements
themselves.

## No provider reaches the known snapshot

History-visible and provider-reachable are separate facts. An
announcement recorded at intake makes a snapshot *known*; only a
decodable `node_addr` from a reachable peer makes it *fetchable* —
and v0 serves content only from the announcing peer (no replication
serving: one address per snapshot, `transport::routes::publish_recorded_routes`).
When nothing serves, every layer below reports absence upward and the
waiter fails bounded. What each case leaves visible, what fails, and
what retries:

- **Known snapshot, no route.** An announcement with an absent or
  undecodable `node_addr` publishes nothing; the plan reports
  absence (`Ok(None)` is genuine absence — nothing to ask,
  `missing_bytes_are_absence_not_error` in
  `crates/wyrd-sync/src/bulk/tests_bulk.rs`, and the undecodable
  skip is counted by
  `undecodable_route_publishes_nothing_and_counts_the_skip` in
  `crates/wyrd-sync/src/transport/routes.rs`). Visible: the
  recorded announcement — snapshot id, epoch, membership binding.
  Routes never enter classification, so a snapshot whose body this
  engine holds still classifies and projects; the failure comes
  later. Fails: `open()` blocks to the want deadline, then `EIO`.
  The deadline-to-`EIO` half is pinned at the registry
  (`wait_returns_on_success_and_on_deadline` in
  `crates/wyrd-core/src/want.rs`) and at the FUSE boundary for
  chunk reads under a materialized tree
  (`read_deadline_is_eio_and_releases_the_want` in
  `crates/wyrd-daemon/src/fuse/tests_want.rs`). The manifest-chain
  case is pinned in two halves, split where the architecture forces
  the split: the hostile-representation walk (corrupt served plus
  absent, nothing committed) at the plan level
  (`corrupt_and_absent_tree_representations_commit_nothing` in
  `crates/wyrd-sync/src/runtime/fetch/tests_fetch.rs`), and the
  blocking open itself — deadline elapsed, `EIO`, registry drained,
  second open re-registers — at the FUSE boundary
  (`manifest_chain_open_fails_bounded_eio_while_tree_unmaterialized`
  in `crates/wyrd-daemon/src/fuse/tests_want.rs`). One test cannot
  cover both: once the durable facts call the tree local the plan
  correctly stops re-driving its walk, while the install gate needs
  present trees — so the walk is staged pre-install and the boundary
  against post-install loss. Retry: the next open re-registers
  the want; a re-announced route is fetched once its cooldown
  lapses (property 8 above), so recovery needs a new announcement,
  never a new caller.
- **Snapshot body or manifest unavailable.** An announcement whose
  body never arrives leaves the snapshot unadopted: a snapshot with
  unrecorded parents classifies
  `Classification::Pending(Pendency::UnknownParent)` and never
  becomes a live head (`authorization/classify.rs`), so the
  projected namespace never contains paths from it — `ENOENT`, not a
  hang. The announcement itself stays recorded and stays advertised
  as known; intake neither commits unverified bytes nor poisons the
  chain. Pinned end to end by
  `body_never_arriving_leaves_the_snapshot_unadopted_and_paths_enoent`
  in `crates/wyrd-contracts/src/sync_contracts.rs` (recorded but not
  live, paths `ENOENT`, child classifies
  `Classification::Pending(Pendency::UnknownParent)`,
  and the stall heals cleanly once the bytes arrive).
- **File content unavailable.** Chunks whose representations name no
  reachable provider are absence at the object level: the fetch walk
  tries every candidate the walk reaches (property 8), genuine
  absence returns `Ok(None)`, and the waiter still fails bounded
  with `EIO` — absence is not an error in the transport, but it is a
  failed open at the boundary. Corrupt or unreachable
  representations fall back to the next recorded representation
  inside the walk; hash/AEAD mismatch is never committed.

In all three cases the timeout cancels the wait, not the fetch
(property 6): a concurrent success still publishes and caches.
And in all three cases v0.2 provides no way back: stranded local
content has no sanctioned recovery path and there is no
root-recovery workflow — both book to v0.3 (`ROADMAP.md`, known
limitations). A peer that holds the epoch material but never learns
a snapshot id (the late-joiner horizon) is the same shape of absence
from the other side: keys without knowledge fetch nothing.

## Locking discipline

Established by the store-lock work and extended here — normative:

1. Fetch network I/O runs under **no view lock and no store guard**:
   `execute_plan` addresses the store through `SharedStore` per-op
   handles; the view write lock is taken only for the bounded publish
   step. This is why a slow transfer cannot stall serving — the
   critical path is network → verified store → projection → short
   write lock.
2. The WantRegistry gets its **own lock** — never the view lock,
   never the store lock. FUSE registers under it and waits; the loop
   drains it per pass.
3. Store guards are per-op, synchronous, and never held across a
   fetch call or a waiter wait.
4. FUSE and the daemon loop never both mutate synchronization state;
   the engine remains the single authority.

## CLI

Migrate argv parsing to **clap derive** in this PR — mechanically
boring: existing commands → derive structs → same semantics. No
configuration hierarchy, environment handling, credential loading,
command renaming, or output-format changes ride along. The
credential-file hardening (0o600, O_NOFOLLOW, bounds, zeroizing)
stays in-repo and is untouched by clap.

## PR boundary

This PR lands the demand machinery: announcement `node_addr` + want
registry + blocking open + read-side demand + CLI composition, proven
against the existing `BulkSource` contract. The transport-identity
distribution that makes maps real (announcement Bao roots, author
signature over the announcement, sealed-manifest-envelope routing
table, serving router) is fanned out to
`feat(sync): distribute transport identities (BaoRoot) and author-sign
announcements` — it is protocol work the demand path consumes, and the
serving-router storage strategy needs its own measured decision
(iroh-blobs 0.103 has no `Store` trait to implement).

Commit plan: this design doc → clap migration → announcement
`node_addr` → want registry + blocking open → docs status.

Test matrix (each locks a decided invariant):

- **Address auth binding**: the `node_addr` is part of the sealed
  plaintext; tampering fails verification and never redirects a
  fetch.
- **Stale address**: announcement names a dead node_addr → fetch
  fails → no invalid object committed → the announcement and its
  content identity remain valid.
- **Dead route beside a live one**: the same representation names a
  dead provider first and the live provider second → under a pass
  budget far shorter than a dead dial, the run still attempts the
  live route and fulfills → a re-announced route recovers without a
  restart once its cooldown lapses, and a dead candidate never
  starves the rest (an early slow-but-live candidate gets a floored
  share; a subdivided share that expires reports a counted,
  unstriking deadline with burn-backoff, while a full-share expiry
  still strikes).
- **Want coalescing**: `Want(X)` ×3 → one in-flight X → three waiters
  complete (and a terminal failure wakes all three with failure).
- **Timeout then completion**: want times out → `EIO` → materialization
  completes anyway → identity cached → next open succeeds
  immediately.
- **Registry overflow**: pending wants beyond the bound fail
  registration with `EIO`; no silent drop.
- **Read-side demand**: a read of an unmaterialized chunk enqueues and
  blocks bounded; the served bytes are verified content; a second
  read is local.
- **Serve surface**: a requested path (not a `StorageId`) is not
  servable; the router answers object lookups only.
- **Loopback iroh end-to-end**: two daemons, announcement + serve +
  demand + blocking open + read, over the loopback transport the
  bulk-source tests already use. *(Landed as contract 13; the serving
  router lives in the transport layer with its client half.)*