# wyrd-sync

Wyrd's peer-to-peer replication layer: iroh transport, snapshot exchange,
encrypted manifests, roles × materialization.

## What belongs here

- iroh endpoint, gossip, and blob-transfer wiring (transport only)
- Snapshot announcements and encrypted manifest exchange
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

## What does not belong here

Merging (Wyrd keeps both heads instead of merging), garbage collection (the
store is append-only for now), and any filesystem presentation (that is
`wyrd-fuse`).

## Version policy

The iroh version set is validated as a set — change all three together and
run the full test suite.
