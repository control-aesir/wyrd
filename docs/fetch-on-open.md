# Fetch-on-Open

Normative design for demand-driven fetch: the daemon serving its
objects over iroh, peers announcing how to reach them, and the live
mount blocking on `open()` until the bytes it needs arrive. One
vertical feature (announcement schema, serving, demand channel,
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
                 │  SnapshotId · epoch · NodeAddr │
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
FUSE open/read ── Want channel ─► LiveDaemon loop ─► engine plan
```

## Peer addressing

The snapshot announcement gains the sender's current **`NodeAddr`**
(routing metadata inside the authenticated sealed plaintext — same
envelope, same signature, no sidecar channel). What an announcement
then means:

> This peer claims to have the material for snapshot S, and here is
> where you may attempt to retrieve it.

Rules, all decided:

1. **Routing metadata, not identity.** `ContentId ≠ StorageId ≠
   NodeAddr`; nothing is ever derived from an endpoint. Endpoint
   failure never invalidates the advertised content.
2. **Authenticated association.** The endpoint rides inside the
   announcement's sealed plaintext — never alongside it. An
   unauthenticated endpoint would be a redirection surface even
   against unforgeable announcements.
3. **Untrusted infrastructure.** The announcement proves only
   *peer → endpoint* association. The endpoint may lie, vanish, or
   serve garbage; Bao verification and content hashing reject all of
   it before `insert_verified`. Zero-trust storage is unchanged.
4. **Replaceable, not durable.** Announcements are mutable routing
   advertisements; snapshots stay immutable. Endpoint fields never
   enter `Snapshot` or any content-addressed object — an address
   change must never look like a snapshot change.
5. **Wyrd invents no address format.** The announcement carries
   iroh's `NodeAddr` representation; relay fallback and address
   selection remain iroh's responsibility.
6. Content verification remains the only admission control: a
   transfer counts if and only if it proves the advertised identity.

## Daemon serving

The daemon (composition layer) owns an iroh-blobs `Router` serving
from the local object store. The engine never learns iroh exists; the
serve surface is **object-oriented, not filesystem-oriented**:

- answer: "can I prove this `StorageId` exists in my local store?" →
  stream its ciphertext;
- never: "can I read this filesystem path?";
- serving never exposes keys or plaintext, and never serves anything
  outside the content-addressed object space. An arbitrary file in
  the drive directory is not servable.

v0 posture: serve whatever the store holds; no admission control
beyond the content-addressed lookup itself (members are admitted via
`trust.md`; an admitted member may pull any object of the drive it
can name).

## Demand channel

One producer, one consumer, one authority — FUSE never performs
synchronization directly and never calls the engine, bulk source, or
store from its own thread:

```text
FUSE open/read (demand producer)
      │  Want{ content identity, deadline }
      ▼
   Want channel (bounded)
      ▼
LiveDaemon loop (consumer, existing task)
      │  expands demand: one open may need
      │  snapshot → dir tree → file tree → chunks
      ▼
engine plan + IrohBulkSource fetch
```

- The demand unit is a `Want` naming the required content identity,
  not an opaque "fetch something" — the waiter waits on the exact
  missing materialization, which is what makes timeout, dedup,
  cancellation, and progress well-defined.
- Merkle-chain expansion belongs to the materialization/engine layer.
  The FUSE contract stays: "make this path readable within the
  deadline" — never "fetch object X".
- `open()` on non-local content enqueues demand and **blocks with a
  bounded timeout**, showing `Fetching` for the file's materialization
  while waiting; it serves once the required objects are verified and
  published, and fails with `EIO` on deadline expiry. A timeout never
  fabricates a partially readable file.
- The timeout bounds **materialization of the requested objects**, not
  a sync pass: the waiter wakes when the specific identities arrive,
  not when unrelated daemon work happens to finish.
- The view is published only after verified materialization; readers
  never see half-served projections.

## Locking discipline

Established by the store-lock work and extended here — normative:

1. Fetch network I/O runs under **no view lock and no store guard**:
   `execute_plan` addresses the store through `SharedStore` per-op
   handles; the view write lock is taken only for the bounded publish
   step. (This is why a slow transfer cannot stall serving.)
2. The want registry (pending wants, waiters, in-flight marks) gets
   its **own lock** — never the view lock, never the store lock.
   FUSE enqueues under it and waits; the loop drains it per pass.
3. Store guards are per-op, synchronous, and never held across a
   fetch call or a waiter wait.
4. FUSE and the daemon loop never both mutate synchronization state;
   the engine remains the single authority.

## CLI

The binary surface grows (`--peer`-style options or none at all, since
discovery is announcement-driven; timeouts; status). Migrate argv
parsing to **clap derive** in this PR: subcommand structs replace the
hand-rolled option surgery in `main.rs`; credential-file hardening
(stays in-repo: 0o600, O_NOFOLLOW, bounds) is unaffected. No other
arg crates.

## PR boundary

One vertical feature, one PR: announcements + serving + demand +
blocking open + CLI composition. Intermediate states cannot
demonstrate the feature, and none of it redesigns the sync protocol —
the announcement schema gains a field; everything else is new plumbing
around decided invariants.

Commit plan: this design doc → clap migration → announcement endpoint
+ serving router → want channel + blocking open → docs status. Tests
along the way: announcement auth binding (endpoint inside sealed
plaintext), serve-surface object-only contract, want-channel
exactly-once/dedup under the daemon loop, bounded-open timeout →
`EIO`, and the existing contracts suite extended with a
fetch-on-open-over-loopback iroh case.