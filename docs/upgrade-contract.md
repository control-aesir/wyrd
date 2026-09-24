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
   `COMMIT_VERSION`; control messages carry `CONTROL_VERSION`.
   Documented exception: durable fact *payloads* are versioned
   before the v1 freeze (open issue, v0.9.0 milestone), so until
   then replay normalizes only the envelope layer and the payload
   clause of this invariant is acceptance-tested as ignored, not
   as passing.
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
10. **Fail closed on the unknown, with one intentional exception.**
    Unknown envelope versions refuse (`EnvelopeError::UnknownVersion`)
    and unknown control versions refuse (`ControlError::UnknownVersion`);
    a known record tag with an unparsable payload poisons the commit
    file so open and resync refuse it. The exception is unknown record
    tags, which are skipped: a deliberate, bounded forward-compatibility
    rule (skip, never reinterpret — unknown bytes are never silently
     read as something else). (This is also the pre-v1 contract: until
     the format freezes, every alpha may break compatibility, and the
     breakage announces itself.)

   The rotation delivery is versioned in its header byte and moved
   `0x01 -> 0x02` when the owner proof was added (`ROTATION_VERSION`).
   Version `0x01` plaintext carried two blobs (transition, wrapped
   capability); `0x02` carries three (those plus the owner proof). The
   bump is what makes a `0x01` delivery fail loudly as
   `UnknownVersion` rather than parse as a `0x02` document missing its
   third blob. This is a deliberate, announced incompatibility under
   the pre-v1 rule above, not a silent reinterpretation: an old sealed
   rotation stops being acceptable and the owner re-mints. The
   capability *wrap* format is deliberately untouched, so
   bootstrap/invitation delivery is unaffected.

## What this forbids

- In-place object rewrites (`old object -> rewrite -> new object`).
- "Upgrade the whole drive" migrations as a precondition for ordinary
  releases. An explicit migration command, if one ever exists, is for
  optional optimization, never basic compatibility.
- Versioning formats by software version (`0.5 -> format 0.5`). One
  software release supports many protocol versions; the numbers stay
  decoupled.

## Verification (implemented, with three blocked halves)

`wyrd-contracts` carries one named test per invariant direction
(catalog 23-33), over fixture stores checked in under
`tests/fixtures/stores/<release>/`. One fixture exists: the `dev`
harness-smoke store; per-release fixtures continue under
their tag with each release. (The `v0.1.0-alpha.1` fixture went out
with the reader-set format break: pre-v1 alphas may break
compatibility, and no legacy transition decoder is carried for
unshipped software. The next release cuts a fresh fixture and
re-enables cross-release replay.) Three tests stay deliberately ignored
until their blockers land: fact-payload replay (invariant 2's
payload clause, pending the v0.9.0 payload-versioning issue),
previous-release replay (invariant 3's cross-release form, pending
the next release fixture), and the full version matrix
(invariant 5's matrix half, pending capability negotiation). Release
checklist, so this coverage cannot silently remain absent: cutting a
release checks in `tests/fixtures/stores/<tag>/` and re-enables
`upgrade_previous_release_store_replays` against it. The list below is the acceptance set for
the contract issue — one bullet per invariant, in the same order:

1. new encodings are new representations: old objects keep their
   ContentIds and stay readable, new writes use the new representation,
   and history is byte-preserved across the upgrade
2. every persistent format carries its explicit version; the next release
   reads previous versions, writes oldest-compatible on demand, and
   replays previous durable facts into current records (payload
   replay ignored until fact payloads are versioned)
3. old formats remain readable for the supported window, proven by
   the previous-release fixture replaying under the current build;
   no release destructively rewrites immutable objects, snapshots,
   or history
4. derived indexes rebuild from previous state by replay; nothing
   authoritative is lost
5. mixed-version peers synchronize within the documented capability matrix
6. a software upgrade never emits a membership transition; the transition
   chain, not the binary, defines authority
7. old-epoch objects remain decryptable; new epochs respect capabilities
8. migrations, if any, land as ordinary snapshot-producing operations;
   history is never rewritten into the newest representation
9. an interrupted upgrade reopens without a separate recovery migration
10. unknown envelope and control versions and unparsable known-tag
    payloads refuse loudly with their names; unknown record tags skip
    as the one intentional forward-compatibility exception
