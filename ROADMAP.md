# Roadmap

This file tracks the implementation order for Wyrd. The normative contracts
live in `docs/object-model.md`, `docs/trust.md`, `docs/epochs.md`, and
`docs/sync-and-peers.md`; this roadmap stays directional.

## Current Boundary

The protocol/core layers are effectively frozen for v0:

- format and identity types
- canonical serialization and decoding
- membership and snapshot authorization
- epoch keys, capabilities, bootstrap framing, and escrow records
- control-plane message set and mailbox/signing trait boundaries

What remains is the runtime system that makes those primitives behave like a
real distributed filesystem.

## Phase 1: Runtime Sync

Goal: turn protocol primitives into a crash-safe, reconnecting sync engine.

Tracked by:

- `feat(sync): runtime sync engine` (`nostr:nevent1qqsd3u6j08rq9n0u0k9tjl4jp88fqjjktrp2pnqfr0g4tl3rwh425xgpz9mhxue69uhkwunpwdczuap49eehgv5jzw2`)
- `feat(sync): durable local state and crash recovery` (`nostr:nevent1qqszjy7pcdmf7kztts3q048dr2d46zmjccjq2p5zl5tw5ndg9hgk6tcpz9mhxue69uhkwunpwdczuap49eehgp4ul4q`)
- `feat(sync): control-plane transport wiring` (`nostr:nevent1qqswa6y6lwxywrnq5gt7w6v25gq9dz37qw7pq2cz63uppl3ajwnzh7cpz9mhxue69uhkwunpwdczuap49eehgtxs4lc`)

Scope:

- durable membership, snapshot, manifest, capability, and materialization state
- crash recovery and restart reconciliation
- mailbox relay pool and signer-client wiring
- bulk object transport and backpressure

## Phase 2: Minimal Filesystem Slice

Goal: prove the runtime can surface a real drive through a filesystem API.

Tracked by:

- `feat(fuse): minimal read-only mount slice` (`nostr:nevent1qqs9ews64fvne43dvzszggedn789kz4ylyfj88qxzy7epvqwq3wa5fgpz9mhxue69uhkwunpwdczuap49eehgzyghwf`)

Scope:

- read-only mount
- lookup, readdir, open, read, stat
- remote-only fetches through the documented materialization boundary

## Phase 3: Recovery Completion

Goal: make root recovery and historical restoration operational end to end.

Tracked by:

- `feat(sync): recovery protocol completion` (`nostr:nevent1qqszq7ctvnagpkzwdcfyjs2u6ezqw2qrvgcqtsnawrugnz2yxarfxhspz9mhxue69uhkwunpwdczuap49eehgql62dp`)

Scope:

- root reconstruction workflow
- escrow record retrieval and replay
- historical epoch restoration
- recovery snapshot creation

## Phase 4: Hardening

Goal: make the protocol surfaces resilient under adversarial and malformed inputs.

Tracked by:

- `docs(sync): state the ingest decode-cost bound` (`nostr:nevent1qqstgq2uqm2vtf4efjc6hdah5k4cl856c08vakzn7lmewqkgtew8gscpz9mhxue69uhkwunpwdczuap49eehgf3hxu4`)
- `test(sync): capability and canonical-apply property follow-ups` (`nostr:nevent1qqsxestle2hqna4lj0794qc8shns9p4nk9r4cd0pxy8rhap28thtd4cpz9mhxue69uhkwunpwdczuap49eehg3u5ztw`)
- `test(sync): fuzz protocol decoders` (`nostr:nevent1qqs94gh4yjy66kcllmxze7dtu8n0jed3anlz0w7jpjs9rcm3gc7e2lgpz9mhxue69uhkwunpwdczuap49eehg2jard5`)

Scope:

- decode-cost and allocation bounds
- property coverage for canonical state transitions
- fuzzing for envelope and decoder surfaces

## Post-v1

Garbage collection stays post-v1.

Wyrd's current contract is append-only history, immutable objects, and
explicit state changes. GC needs a retention/acknowledgement design that is
separate from the core protocol boundary.
