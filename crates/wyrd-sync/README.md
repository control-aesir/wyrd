# wyrd-sync

Wyrd's peer-to-peer replication layer: iroh transport, snapshot exchange,
encrypted manifests, roles × materialization.

## What belongs here

- iroh endpoint, gossip, and blob-transfer wiring (transport only):
  `IrohBulkSource` is the network bulk backend; the `BulkSource` trait and
  its memory fake serve the fetch contracts
- Author-signed snapshot announcements: Bao transport roots as the
  verified-fetch addresses, BIP-340 over the drive-bound challenge, fork
  gating at intake, and route updates (last accepted route wins)
- The runtime sync engine: durable fact log (commit/replay, crash and
  torn-commit recovery), restart reconciliation, and the fetch plan —
  transport-first with the announced identity enforced on every route
- Author-side manifest generation: tree walk, chunk and manifest sealing,
  vault import, and announcement, fail-closed on missing chunks
- The durable serving vault (`serving.rs`): a sealed-bytes CAS keyed by
  transport root; authored envelopes are imported at write time and served
  after every restart, with `VaultSource` layering durable runtime state
  over it as the serving projection
- The encryption boundary: per-object AEAD, drive-key manifests, and the
  content→storage mapping — vault peers stay fully opaque
- Two-phase content arrival: announcements/manifests first, object content
  lazily (this is what lets vault peers be offline for weeks)
- Materialization states (`REMOTE_ONLY` / `CACHED` / `PINNED`) and pin/evict
  policy — device-local decisions, never drive decisions
- Peer roles (vault / mirror) and admission (tickets), liveness
- Nostr identity verification: snapshot signatures against member pubkeys,
  encrypted control plane for membership/rotation (never public relays)
- Scrub detection downstream of the store and repair from other peers
  (pending: needs the serving router)

## What does not belong here

Merging (Wyrd keeps both heads instead of merging), garbage collection (the
store is append-only for now), and any filesystem presentation (that is
`wyrd-fuse`).

## Status

The protocol/core and runtime sync layers are in place and under test:
control-plane intake with ingest limits, transport identity distribution,
fetch-on-open demand machinery, the vault serving path, and recovery.
Pending: the real-iroh serving router peers dial into (`IrohBulkSource` is
the client side), multi-relay supervision, NIP-46 remote signing, and
scrub/repair wiring.

## Version policy

The iroh version set is validated as a set — change all three together and
run the full test suite.