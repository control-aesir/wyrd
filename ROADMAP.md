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

Phases 1 to 4 shipped their tracked scope: the runtime sync engine, the
read-only filesystem slice, root recovery, and the hardening passes are in
place and under test. The frontier is the live network and the write path
(see Current Focus below).

## Phase 1: Runtime Sync — shipped

Goal: turn protocol primitives into a crash-safe, reconnecting sync engine.

Tracked by (all applied):

- `feat(sync): runtime sync engine` (`nostr:nevent1qqsd3u6j08rq9n0u0k9tjl4jp88fqjjktrp2pnqfr0g4tl3rwh425xgpz9mhxue69uhkwunpwdczuap49eehgv5jzw2`)
- `feat(sync): durable local state and crash recovery` (`nostr:nevent1qqszjy7pcdmf7kztts3q048dr2d46zmjccjq2p5zl5tw5ndg9hgk6tcpz9mhxue69uhkwunpwdczuap49eehgp4ul4q`)
- `feat(sync): control-plane transport wiring` (`nostr:nevent1qqswa6y6lwxywrnq5gt7w6v25gq9dz37qw7pq2cz63uppl3ajwnzh7cpz9mhxue69uhkwunpwdczuap49eehgtxs4lc`)

Landed:

- durable membership, snapshot, manifest, capability, and materialization
  state — durable fact log, replay, restart reconciliation under test
- crash recovery and restart reconciliation, including torn-commit recovery
- transport identity distribution: BaoRoot announcements, author-signed
  routing columns, announcement fork gating at intake with route updates
- bulk object transport type (`IrohBulkSource`) and the fetch plan that
  consumes the announced identities

Remaining in this phase: the serving router peers dial into (real-iroh
loopback in the `wyrd` binary), NIP-46 remote signing, and bulk
backpressure under live network conditions.

## Phase 2: Minimal Filesystem Slice — shipped

Goal: prove the runtime can surface a real drive through a filesystem API.

Tracked by (applied):

- `feat(fuse): minimal read-only mount slice` (`nostr:nevent1qqs9ews64fvne43dvzszggedn789kz4ylyfj88qxzy7epvqwq3wa5fgpz9mhxue69uhkwunpwdczuap49eehgzyghwf`)

Landed:

- read-only FUSE mount via the daemon (`wyrd init`, `wyrd mount`)
- lookup, readdir, open, read, stat over the mount-free view
- remote-only fetches through the documented materialization boundary:
  fetch-on-open demand machinery (want registry, blocking open/read with a
  bounded `EIO` deadline) proven against the bulk-source contract

Remaining in this phase: write support (the mount is read-only by design
until the write path lands).

## Phase 3: Recovery Completion — shipped

Goal: make root recovery and historical restoration operational end to end.

Tracked by (applied):

- `feat(sync): recovery protocol completion` (`nostr:nevent1qqszq7ctvnagpkzwdcfyjs2u6ezqw2qrvgcqtsnawrugnz2yxarfxhspz9mhxue69uhkwunpwdczuap49eehgql62dp`)

Landed: root reconstruction workflow, escrow record retrieval and replay,
historical epoch restoration, and recovery snapshot creation.

## Phase 4: Hardening — shipped

Goal: make the protocol surfaces resilient under adversarial and malformed inputs.

Tracked by (all applied):

- `docs(sync): state the ingest decode-cost bound` (`nostr:nevent1qqstgq2uqm2vtf4efjc6hdah5k4cl856c08vakzn7lmewqkgtew8gscpz9mhxue69uhkwunpwdczuap49eehgf3hxu4`)
- `test(sync): capability and canonical-apply property follow-ups` (`nostr:nevent1qqsxestle2hqna4lj0794qc8shns9p4nk9r4cd0pxy8rhap28thtd4cpz9mhxue69uhkwunpwdczuap49eehg3u5ztw`)
- `test(sync): fuzz protocol decoders` (`nostr:nevent1qqs94gh4yjy66kcllmxze7dtu8n0jed3anlz0w7jpjs9rcm3gc7e2lgpz9mhxue69uhkwunpwdczuap49eehg2jard5`)

Landed: decode-cost and allocation bounds, property coverage for canonical
state transitions, and fuzzing for the envelope and decoder surfaces.

## Current Focus: The Live Network and the Write Path

The serving router loopback has landed: a real-iroh endpoint over the
durable vault serves peer fetches by transport root, announcement
`node_addr` routes publish into the fetch plane on every sync pass, and a
serving restart's route update rewires serving (contract 13). What comes
next, roughly in order:

- multi-relay mailbox: cancel-aware recovery supervision for a relay pool
  (`refactor(daemon): cancel-aware recovery supervision for a multi-relay
  mailbox`)
- external relay interoperability coverage (`test(daemon): cover external
  relay interoperability`)
- write support behind the FUSE mount: designed in `docs/write-path.md`
  (`docs(write-path): design the mounted write path`), then
  `feat(format): mkdir, rmdir, and rename mutations` and
  `feat(fuse): mounted write operations`, on the composition seam from
  `refactor(daemon): make runtime ownership and projection publication
  explicit`; automatic peer repair follows
- NIP-46 signer-session client wiring

## Post-v1

Garbage collection stays post-v1: it needs a retention/acknowledgement
design that is separate from the core protocol boundary. The current
contract is append-only history, immutable objects, and explicit state
changes.
