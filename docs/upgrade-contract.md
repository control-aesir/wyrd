# Upgrade and Migration Contract

**Normative** for every change that touches a persistent format or the sync
protocol. The goal: a Wyrd upgrade is normally a program upgrade, not a
data migration. Old state stays valid; newer implementations learn to
interpret it.

## Why this is tractable for Wyrd

Most user data is immutable and content-addressed. That lets the
*interpretation layer* evolve without rewriting the data underneath. The
SQL-shaped problem (`ALTER TABLE` over mutable rows) becomes a replay
problem (old records in, current representation out).

## Compatibility levels

- **Level 1 — data-compatible.** A newer Wyrd opens an old local store
  without migration. Mandatory before 1.0.
- **Level 2 — peer-compatible.** A newer Wyrd synchronizes with an older
  Wyrd. Requires protocol negotiation and representation compatibility.
- **Level 3 — rolling-upgrade compatible.** A drive holds devices running
  different Wyrd versions for an extended period without simultaneous
  upgrades. The gold standard for a P2P application.

## Read compatibility vs write compatibility

Releases are not required to write every format they read:

- **Read:** each release reads its own formats plus every format back to
  the oldest supported version (at least one previous format version
  remains readable by the next release).
- **Write:** each release writes the oldest mutually supported
  representation — v1-compatible objects when the peer or store requires
  them, newer representations only where supported.

## Upgrade invariants

1. **Immutable data is never migrated in place.** A new encoding is a new
   object representation with an explicit version; old objects keep their
   ContentIds and stay readable. New writes use the new representation.
2. **Every persistent format has an explicit version.** Envelopes carry
   `wyrd_format::envelope::VERSION`; commit envelopes carry
   `COMMIT_VERSION`; control messages carry `CONTROL_VERSION`. Durable
   fact payloads are versioned before the v1 freeze (open issue), so
   replay can normalize `v1`/`v2` payloads into the current record.
3. **Old formats remain readable for the supported window** (read rule
   above). No release performs destructive in-place rewriting of
   immutable objects, snapshots, or history.
4. **Derived state rebuilds; it is never authoritative.** Indexes, serving
   maps, and materialization caches derive from durable facts by replay.
   An upgrade rebuilds them instead of migrating them. No derived cache
   or index is the sole copy of user data or protocol history.
5. **Protocol negotiation is capability-based**, not software-version
   based. `CONTROL_VERSION` equality is the pre-v1 gate; before v1 it
   grows into advertised capabilities with oldest-mutual selection.
6. **Membership epochs, cryptographic epochs, software versions, and
   protocol versions are independent.** An implementation upgrade must
   never implicitly become a membership transition; the transition chain,
   not the current binary, defines authority.
7. **Cryptographic evolution is additive.** Epoch secrets stay fresh and
   un-derived; objects keep the construction of their epoch, so a new
   construction arrives with a new epoch, never with a rewrite of history.
8. **Snapshot history is a permanent protocol archive.** Upgrades extend
   the DAG with representations the recipient understands; they never
   rewrite history into the newest representation. A genuine format
   migration is itself an ordinary snapshot-producing operation
   (`derived-from` metadata), which keeps it immutable, auditable,
   reversible, and replicated.
9. **Interrupted upgrades reopen.** Commits land temp + fsync + rename, so
   a torn write never becomes visible; a node opens its store after an
   interrupted upgrade without a separate recovery migration.
10. **Fail closed on the unknown.** Each boundary names its behavior
    for what the build does not understand: an unknown envelope
    version refuses (`EnvelopeError::UnknownVersion`), an unknown
    control version refuses (`ControlError::UnknownVersion`), an
    unknown record tag is skipped for forward compatibility, and a
    known tag with an unparsable payload poisons the commit file so
    open and resync refuse it. Skipped is not reinterpreted: unknown
    bytes are never silently read as something else. (This is also
    the pre-v1 contract: until the format freezes, every alpha may
    break compatibility, and the breakage announces itself.)

## What this forbids

- In-place object rewrites (`old object -> rewrite -> new object`).
- "Upgrade the whole drive" migrations as a precondition for ordinary
  releases. An explicit migration command, if one ever exists, is for
  optional optimization, never basic compatibility.
- Versioning formats by software version (`0.5 -> format 0.5`). One
  software release supports many protocol versions; the numbers stay
  decoupled.

## Verification (planned, not yet implemented)

`wyrd-contracts` will carry one named test per invariant direction, over
fixture stores checked in under `tests/fixtures/stores/<version>/`.
Status today: neither the upgrade contracts nor the fixture tree exist —
the catalog in `crates/wyrd-contracts/src/lib.rs` covers the current
protocol and format contracts only. Until the tests land, this document is
the rulebook and the list below is the acceptance set for the contract
issue — one bullet per invariant, in the same order, so the suite is one
named test per invariant direction with no gaps:

1. new encodings are new representations: old objects keep their
   ContentIds and stay readable, new writes use the new representation,
   and history is byte-preserved across the upgrade
2. every persistent format carries its explicit version; the next release
   reads previous versions, writes oldest-compatible on demand, and
   replays previous durable facts into current records
3. old formats remain readable for the supported window; no release
   destructively rewrites immutable objects, snapshots, or history
4. derived indexes rebuild from previous state by replay; nothing
   authoritative is lost
5. mixed-version peers synchronize within the documented capability matrix
6. a software upgrade never emits a membership transition; the transition
   chain, not the binary, defines authority
7. old-epoch objects remain decryptable; new epochs respect capabilities
8. migrations, if any, land as ordinary snapshot-producing operations;
   history is never rewritten into the newest representation
9. an interrupted upgrade reopens without a separate recovery migration
10. anything outside the matrix fails with a named error: unknown
    envelope and control versions refuse loudly, unknown record tags
    skip, and unparsable known-tag payloads poison the commit
