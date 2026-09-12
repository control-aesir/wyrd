# Wyrd Architecture

One page. Read this, then the focused docs:

- `object-model.md` — **normative v0 format spec**: identities, canonical
  encoding, chunking, snapshot DAG, manifests, conflicts, decision record
- `sync-and-peers.md` — transport, encrypted manifests, peer roles,
  materialization policy, two-phase content
- `trust.md` — **normative** trust model: Nostr identity boundary (BIP-340),
  root custody, epoch key hierarchy, control plane, capability security
  properties, recovery design
- `epochs.md` — **normative** membership/epoch state machine: transition
  validation, membership conflicts, snapshot → membership binding, snapshot
  authorization, classification, recovery
- `fetch-on-open.md` — **normative** demand-driven fetch design:
  announcement endpoints, daemon serving, want channel, blocking open

## The system in one sentence

Wyrd is an encrypted, content-addressed, append-only filesystem whose
snapshots describe a logical drive, while individual devices materialize
arbitrary subsets of that drive locally.

## Crate map

| Crate | Responsibility | Depends on |
|---|---|---|
| `wyrd-format` | DriveId/ContentId/StorageId/SnapshotId (distinct types), canonical encoding, chunking, Merkle trees, snapshot DAG, `ObjectStore` | blake3, hex, thiserror only |
| `wyrd-sync` | iroh transport, snapshot announcements, encrypted manifests, fetch/evict, peer roles | `wyrd-format`, iroh stack, nostr crate (BIP-340, NIP-44, NIP-46) |
| `wyrd-fuse` | Mount-free drive view: lookup, readdir, open, read, stat, conflict surfacing | `wyrd-format` only |
| `wyrd-daemon` | Composition: engine + view, presentation backends (FUSE today; mobile file surfaces later) | `wyrd-sync`, `wyrd-fuse`, `fuser` |
| `wyrd-contracts` | Test suite: one named test per architectural contract, composed end to end | all of the above |

Dependency arrows point downward only. `wyrd-format` must never grow a network,
async, or FUSE dependency. `wyrd-fuse` must never know that iroh exists — the
daemon composes sync and fuse. `wyrd-daemon` is that composer: its core is
presentation-agnostic (mobile platforms cannot use FUSE, so the platform
surface is a pluggable backend over the same view); the FUSE adapter is the
first backend, not a property of the core.

## Invariants (hold everywhere, always)

1. **Objects are immutable.** ContentId = domain-separated BLAKE3 of
   plaintext; StorageId = domain-separated BLAKE3 of ciphertext. Both are
   distinct Rust types — the compiler enforces the boundary. Writing the
   same content twice is a no-op.
2. **Deletion is a state change.** A new snapshot without the path; objects
   remain until GC. GC does not exist yet — the store is append-only forever
   in v0.
3. **Snapshots are never rewritten.** The snapshot DAG is append-only; heads
   are the drive's state; "current" is a policy over heads. Snapshots are
   signed with the author's Nostr identity key, bound to the DriveId and to
   the membership transition that authorizes them — Nostr cryptography
   (BIP-340), never Nostr event formats. Only live-lineage eligible heads
   advance the live view; superseded, stranded, and voided forks are
   retained history (`epochs.md`).
4. **Content IDs never reach vaults.** Vaults store ciphertext by StorageId
   and opaque encrypted manifests; they cannot decrypt contents and cannot
   determine plaintext equality from object representation (fresh nonces).
5. **Every ciphertext is AEAD-bound to its version, kind, and ContentId** —
   and decryption success alone is never sufficient; the plaintext must hash
   to the expected ContentId too.
6. **Conflicts keep both heads.** No automatic merge, no lost versions; DAG
   conflict and path conflict are distinct.
7. **Materialization is local policy.** Pin/evict changes what a device
   holds, never what the drive contains.
8. **The projected namespace is the user's data only.** The mounted view
   never introduces synthetic files, directories, or metadata entries —
   it is a projection of the snapshot DAG, not a second metadata
   filesystem layered on top of the drive. View controls (version
   selection, conflict inspection, snapshot selection) are
   path-resolution semantics or out-of-band control APIs; Wyrd's own
   metadata lives in the internal object store, never the mounted
   namespace.

## Non-goals (for now)

- Garbage collection (v0 is append-only indefinitely; the retention/ack
  protocol is a later, serious design task)
- Merging file content three-way (both heads are kept and surfaced instead)
- Full filesystem metadata (mtimes, xattrs, ACLs, resource forks — see the
  explicit list in `object-model.md`)
- Mobile platforms, web, WASM targets
- Windows FUSE (Windows support rides on the CAS being plain files)

## Transport and operational invariants

The iroh stack (iroh 1.0.3, iroh-blobs 0.103.0 fs-store, iroh-gossip 0.101.0)
is validated as a set: bump all three together and run the full test suite.
Hard-won operational rules:

- Supervised tasks restart with capped exponential backoff.
- Every event subscription has a drainer; an undrained subscription wedges
  the sync actor.
- Filesystem watchers declare a lag contract: on `Lagged`, backfill/reconcile
  from state, never from the missed events.
- Self-writes are echo-suppressed (path + hash + TTL) so the watcher never
  re-publishes what the peer just wrote.
- Version ordering uses the deterministic `(timestamp, author)` tiebreak —
  for display only, never content.

## Current status

Pre-alpha. `wyrd-format` implements identities, canonical codecs,
chunking, trees, snapshots, manifests, and membership transition
documents; `wyrd-sync` implements the membership state machine, snapshot
authorization, epoch keys, capabilities, object sealing, escrow records,
the control-plane message set, ingest limits, and the control-plane
transport boundary (NIP-44 mailbox sealing, `Mailbox`/`SignerSession`
traits) — the protocol/core layers are covered by example, conformance,
and generative suites with commit hooks clean. The runtime pieces that
turn those primitives into a full distributed system are still
incomplete: durable snapshot bodies with the engine-backed live-head
projection have landed, the engine can author and durably commit member
snapshots (the local write path), and a drive can be created locally
from scratch (identity, root custody, genesis membership); the daemon
composes a live NIP-59 relay mailbox (`LiveMailbox`: kind 1059 gift
wraps over a durable seen-event-id dedupe log, supervised with relay
health polling and capped-backoff drainer recovery) and the `wyrd` binary
provides local init/mount. The demand machinery for fetch-on-open has
landed (`docs/fetch-on-open.md`): a want registry on its own lock,
blocking `open`/`read` with a bounded deadline (`EIO` on expiry), and
read-side chunk demand — proven against the bulk-source contract; the
transport-identity distribution that makes fetch real against peers
(announcement Bao roots, author-signed announcements, serving router)
is a tracked follow-up. Still open: the NIP-46 signer-session client
wiring, and the
live fetch-on-open transport; garbage collection does
not exist. `wyrd-fuse` is a
mount-free view behind the daemon's FUSE backend. All crypto and sync
work follows `trust.md` and `epochs.md` as normative contracts; the
open tracking issues name what comes next (durable snapshot-body
consumers, runtime sync, recovery completion).

The local `wyrd` CLI mounts a live read-only projection: a supervised
loop drains the NIP-59 control-plane mailbox, admits FUSE demand into
durable `Cached` materialization each pass, refreshes materialization
facts and live heads into the serving view without remounting, and
shuts down cleanly on SIGINT/SIGTERM. `open`/`read` on non-local
content registers a want and blocks bounded (`docs/fetch-on-open.md`);
fetch from peers is not yet wired (no transport-identity distribution,
so the loop runs without a bulk source) and demand therefore surfaces
`EIO` on deadline. Relays arrive as repeatable `--relay` flags;
parsing is clap-derive. Credential
files are supported on Unix, must be regular files owned by the current
user with private permissions, and are bounded and zeroized at the CLI
boundary.
