# Sync and Peers

How Wyrd moves objects and snapshots between devices. `wyrd-sync`
implements the protocol/core boundaries; the runtime wiring that turns
them into a full distributed system is still in progress.

The identity model is defined in `object-model.md` (two identities: Content
ID / Storage ID). This doc describes how peers exchange them.

## Transport

- iroh endpoint with relay/DNS discovery, NAT traversal, and gossip
- Pairing via tickets (one peer generates, the other imports)
- The iroh version set (iroh 1.1.0 / iroh-blobs 0.103.0 fs-store /
  iroh-gossip 0.101.0) is validated as a set and changes as a set

## Runtime sync boundary

The remaining runtime work sits between the protocol primitives and the
filesystem surface:

- persistent local state for membership, snapshots, manifests, materialization,
  capabilities, and pending work
- relay pool / signer-client wiring for the control plane
- bulk object transport and backpressure
- crash recovery and restart reconciliation
- read-only then read/write FUSE integration

That is the next phase after the protocol/core contracts already in `wyrd-sync`.

## Control-plane transport (Nostr mailbox)

The control-plane message set (`wyrd-sync/src/control/`) is transport-agnostic
bytes; `wyrd-sync/src/transport/` wraps it for the Nostr mailbox:

- **Mailbox seal**: every `SealedControl`/`SealedBootstrap` envelope travels
  inside an outer NIP-44 seal between the two devices' Nostr identity keys —
  two independent seals, the inner one authenticity (`trust.md`), the outer
  one relay confidentiality. Recipient discovery addresses the recipient's
  `DeviceId` directly (`trust.md` T16); this is the same traffic-analysis
  exposure as any two-party encrypted messaging, already accepted as
  best-effort.
- **`Mailbox` trait**: the send/receive boundary a relay client implements.
  Synchronous by design, since no concrete relay pool lives in `wyrd-sync`
  yet — every test runs against an in-memory fake, never a live network.
- **`SignerSession` trait**: the NIP-46 `sign_message` boundary
  (`trust.md` "NIP-46 remote signing"); a `nostr-connect`-style client
  implements it, tested here only against an in-memory fake key.
- **Deferred**: the concrete relay pool (subscription management, retry
  backoff, event kind/tag conventions) and the `nostr-connect` session
  negotiation are wiring for whatever composes this crate — the traits above
  are the pinned boundary.

## What is exchanged

- **Snapshot announcements** (small, gossip-propagated): "my head set now
  includes snapshot S, and here is my current `node_addr` for retrieval" —
  signed, verified against known member identity keys (`trust.md`). The
  address is authenticated routing metadata inside the same sealed
  plaintext, never identity and never snapshot content (`fetch-on-open.md`).
  Freshness is operational, not validity: newer announcements do not
  cryptographically invalidate older ones — announcement history is
  append-only, and address selection/fallback is an operational layer
  decision.
- **Encrypted manifests** (hierarchical, per-subtree — see
  `object-model.md`): trees plus the content→storage mapping for every
  object the snapshot references, sealed to the drive. Drive members
  decrypt; vaults store them opaquely.
- **Objects** (ciphertext, addressed by StorageId): pulled on demand, not
  pushed.

Vaults see: opaque blobs, sizes, counts, timing, traffic patterns. Vaults
cannot determine plaintext equality from object representation, and never
see content IDs, paths, or tree structure.

**Layering note:** Wyrd chunks are logical storage/dedup units;
iroh-blobs' Bao chunking is transport verification with range requests and
resumable state. The two are deliberately separate abstractions — Wyrd
rides on iroh's verified streaming instead of duplicating it.

## Cross-device dedup (a manifest protocol, not a vault protocol)

1. Device has plaintext content C, derives ContentId.
2. Before encrypting and uploading, it consults manifests it has received:
   does any member's manifest already map C → some StorageId S?
3. If yes: fetch S, decrypt, verify (AEAD binding + content hash), done —
   no second upload. If no: encrypt with a fresh nonce, upload, publish the
   C → S mapping in its own manifest.

The vault learns nothing in either path. This protocol is why manifest
exchange is eager and object transfer is lazy.

## Two-phase content arrival

Metadata first, content later — and knowledge is layered, not binary. A
device can know history (a snapshot exists) without knowing structure (its
tree), know structure without knowing file metadata, and know metadata
without holding bytes. The materialization states below describe **residency
and policy only** — knowledge levels are tracked separately:

| State | Meaning |
|---|---|
| `REMOTE_ONLY` | known via manifest; content not local; no local storage |
| `CACHED` | content local, fetched by access; evictable by policy |
| `PINNED` | content local; guaranteed retained by user policy |

Fetching is progressive at the object level: an interrupted download leaves
only verified immutable chunks behind, so resume needs no special mechanism.

## Materialization policy vs peer role

Peer role and materialization are independent parameters:

- **Roles:** `vault` (replicates every object, never prunes) and `mirror`
  (participates in live sync, prunable).
- **Materialization policies:** `full`, `partial` (pinned paths), `on-demand`
  (cache-only with size cap).

A desktop is `mirror + full`; a laptop `mirror + partial`; a phone
`on-demand` with a pinned subset; a NAS `vault + full`. Pin/evict decisions
are local device policy — they change what the device holds, never what the
drive contains.

## Encryption and keys

- Objects are encrypted client-side (per-object AEAD, fresh random nonce,
  AAD binding over version/kind/ContentId) before leaving the device — in
  transit and at rest. A wrong manifest mapping fails at the AEAD tag.
- Manifests are sealed to the drive; only drive members can interpret them.
- Snapshots are signed by their author device's identity key; peers reject
  unverifiable snapshots.
- The full key hierarchy, admission, removal, and rotation semantics are
  normative in `trust.md` — **that document gates sync-layer implementation**.

## Peer admission

Any member can author snapshots — authorization comes from membership
state, not drive creation. New devices join through admission and receive
capabilities; there are no guest privileges. Membership is signed,
replicated state that members agree on.

### Post-admission discovery (catch-up obligation)

The bootstrap invitation carries the genesis transition plus the
admission-epoch capability and nothing else. Learning everything after
that is a catch-up obligation on the admitter, not a second protocol:
a durable set of existing control messages, addressed to the newcomer
and retried until acknowledged.

- **Membership:** the authoritative chain suffix after genesis,
  replayed by the newcomer through the normal validation machinery —
  no privileged path, no trust in the pusher beyond signatures.
- **Capabilities:** one wrap per epoch, contiguous from the admission
  epoch to the current epoch. A sparse union is accepted only if the
  capability format and authorization rules prove it safe.
- **Heads:** current head announcements with their retrieval routes,
  re-sent byte-identical to the authors' signed statements.
- **Rotation notices** are informational; transitions plus
  capabilities are authoritative for epoch state.
- **Redundancy without authority:** any member that observes the
  admission may push the same set (intake dedupe makes repeats
  no-ops), but only the admitting authority's committed admission
  transition determines membership. Bootstrap changes
  discoverability, not authorization.
- **Ordering is an optimization:** intake already holds
  membership-unseen messages pending, so the newcomer converges
  regardless of mailbox delivery order. The invariant is eventual
  convergence under arbitrary order and duplication, proven by
  contracts 17–22 in `wyrd-contracts`.

Pre-admission history stays opaque to the newcomer by design: it
holds no old epoch secrets, so old snapshots and manifests are
unreadable to it (`trust.md` revocation boundary). The admission
commit and its catch-up obligations land in one durable batch, so a
crash cannot commit the former while losing the latter.

Known boundary, resolved: catch-up used to span only epochs the
invitation covers, because epoch-key delivery past the invitation was
circular under the envelope rules (a wrap for N+1 sealed under
envelope N+1, openable only with key N+1). Rotation delivery decides
it (option 2, ECDH to the registered key, `trust.md`): post-invitation
epochs converge through the rotation framing, and pre-key offers skip
transiently (retained, counted) until the settling drain goes quiet.
The sender side mirrors this: an obligation with nothing mintable
stays pending and observable via the pending projection instead of
failing its whole pass, and reused sealed bytes are verified against
their obligation before the send that would discharge them.

## Conflicts

No merging. Concurrent publishes create multiple heads; both remain
reachable. **DAG conflict and path conflict are distinct** — multiple heads
does not mean any path differs; the live view computes path-level
differences between heads and surfaces conflicted paths with both versions
(presentation is defined policy, not format). Resolution = publishing a new
snapshot whose parents are all heads. The `(timestamp, author)` tiebreak
orders versions for display only — it never decides content.

Version access is lookup grammar, never stored entries: a trailing `@N` on
a component (`foo@1`) addresses version N of a conflicted `foo`, numbered
deterministically in SnapshotId byte order. The grammar applies only where
the literal path does not exist — real stored names always win — and
`readdir` never lists version-qualified names. SnapshotIds themselves never
enter the user-facing path. Conflict version selection is a property of
path resolution, not of the stored filesystem namespace; the projected
namespace stays the user's data only (invariant 8 in `architecture.md`).

## Operational patterns

- Supervised tasks restart with capped exponential backoff
- Every event subscription has a drainer: an undrained subscription wedges
  the sync actor (do not regress this)
- Filesystem watchers declare a lag contract: on `Lagged`, backfill/reconcile
- Echo suppression for self-writes (hash + TTL) so the watcher never
  re-publishes what the peer just wrote
- Pause/resume defers work instead of dropping it

## FUSE behavior for non-local content (contract between sync and fuse)

The normative design for this boundary — demand channel, blocking open,
timeouts, daemon serving — is `fetch-on-open.md`. FUSE talks to an
abstract materialization interface — lookup, read,
ensure_local, publish — which an application composes from format + sync;
the filesystem layer never knows iroh exists. Internally the fetch state
machine is richer than the POSIX boundary it maps to:

```
RemoteOnly → Fetching → Available | Unavailable | Corrupt
```

with the translation to POSIX errors happening only at the boundary:
opening a non-local path blocks on fetch with visible progress, serves the
read once verified and cached, and fails with `EIO` when no peer is
reachable and the object is not cached. Corrupt objects trigger scrub/repair
before ever surfacing as errors. Eviction never affects the drive — only
what this device holds.
