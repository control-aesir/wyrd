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
   Representation and identity versioning stay separable: a framing-only
   change takes a new envelope version byte and does not fork ContentId;
   the identity fork rides the ContentId derivation context
   (`object-model.md` decision 30). Manifests are the one exception:
   entry versions are seal versions hashed into the manifest payload,
   so a seal-version fork moves the manifest identities that name it.
2. **Every persistent format has an explicit version.** Membership in
   this list is: formats persisted at rest or recorded in signed archive
   state. Sealed objects carry `SEAL_VERSION`; rotation deliveries carry
   `ROTATION_VERSION`; escrow sidecar records carry `ESCROW_VERSION`;
   drive custody records carry `KEYSTORE_VERSION` (owner) and
   `MEMBER_KEYSTORE_VERSION` (member) — the one format that already
   reads two versions at once; node addresses carry `NODE_ADDR_VERSION`
   (recorded in signed announcements); bootstrap envelopes carry
   `BOOTSTRAP_VERSION`; commit envelopes carry `COMMIT_VERSION`;
   control messages carry `CONTROL_VERSION`. Object-envelope framing
   (`wyrd_format::envelope::VERSION`) is versioned under
   `object-model.md` decision 30 instead: framing-only changes do not
   fork ContentId.
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

    Outbox retirement is a new record tag, not a version bump.
    `CapabilitySealedReplaced` (`0x16`) names the sealed fact it
    supersedes and carries its replacement, so a stale obligation
    stays recoverable instead of stuck: replay resolves
    the chain to the newest bytes and leaves the superseded record
    inert. Three triggers reach it — a superseded rotation version
    (the `0x01 -> 0x02` case above), a current-framing seal to a
    superseded registration, and a pre-framing epoch-sealed
    capability fact — all through the same record and the same
    supersession identity. An old node skips the unknown tag (invariant 10's
    exception), so a store written by a new node still opens there —
    it simply keeps treating the superseded bytes as the obligation.
    `0x16` was chosen after `0x13`, which is
    `BootstrapPending`: a tag collision decodes as the wrong fact kind
    rather than skipping, so tag allocation is checked against the
    full set, not against the last value.

    Reconciliation retirement follows the same pattern. The
    `*Reconciled` facts the forget contract (`sync-and-peers.md`
    DG-3) retires obligations with are new record tags — one per
    obligation class — each naming the obligation and the recipient
    statement it retired against, allocated against the full tag set
    like `0x16`. An old node skips them and keeps the obligation
    pending, which is the safe direction: it retries what a new
    node has retired, rather than forgetting what it never proved.

    The stated reconciliation view (`0x18`) is the recipient side of
    the same pattern: the per-class durable evidence (committed
    transitions, held snapshots, installed capability epochs) as the
    recipient saw it, which the recipient's reconciliation statement
    is the transport representation of. An old node skips the unknown
    tag and derives nothing — views are statements, never load-bearing
    for replay, so skipping one loses no state. `0x18` follows `0x17`
    (the announcement route seal); like `0x16`, it was checked
    against the full tag set, not the last value.

    Two semantics are pinned with the tag. A stated view counts as
    evidence iff it is a per-class subset of what derivation computes
    over the same base facts (the exact-set projection): ancestry-
    widened proof predicates live in the comparison logic, never in
    stored statements, so a future predicate change must not
    reinterpret an old `0x18` record. And a statement outside that
    projection is dropped at load with a warning, never replayed and
    never fatal: the claim fails closed while the store stays open —
    no public commit can write a store that will not reopen. The
    local audit identity is the domain-separated digest over the
    canonical (ceiling-free) bytes, distinct from the authenticated
    wire-statement identity retirement references.

    The received reconciliation request (`0x19`) is the sender side
    of the same pattern: the (requester, evidence) pair intake
    commits on first sight, so the set difference (21c) compares
    against durable evidence. Same per-section ceiling and the same
    evidence layout as `0x18`, requester bytes ahead; no subset
    check at load (the sender cannot validate another device's
    holdings against its own log — divergent histories are the case
    being reconciled). An old node skips the unknown tag and keeps
    whatever it had pending, which is the safe direction: it retries
    what a new node would answer from evidence, rather than acting
    on a statement it never read. `0x19` follows `0x18`, checked
    against the full tag set like `0x16`.

    The wire kind is not a format break: the reconciliation request
    rides a new control kind byte (`0x04`) under the unchanged
    envelope version. An old node fails the kind byte closed
    (`UnknownKind`, discarded as terminal poison without a fact) —
    it never misparses a request as another kind, and the sender's
    relay-retained retry keeps the statement available for a new
    node. Additive kinds need no negotiation by design.

    The tag boundary is pinned by
    `the_replacement_tag_is_a_clean_upgrade_boundary`: `0x16` sits
    outside the enumerated pre-replacement set, a commit carrying a
    real replacement loads rather than poisoning the file, and a
    current reader resolves the chain to the replacement bytes. The
    field order and the supersession identity are pinned byte-exact
    alongside it (`replacement_record_layout_is_byte_exact`,
    `supersession_identity_matches_known_answer`); the owner-proof
    construction the replacement supersedes toward is pinned the
    same way (`owner_proof_*` in `wyrd-contracts`).

## What this forbids

- In-place object rewrites (`old object -> rewrite -> new object`).
- "Upgrade the whole drive" migrations as a precondition for ordinary
  releases. An explicit migration command, if one ever exists, is for
  optional optimization, never basic compatibility.
- Versioning formats by software version (`0.5 -> format 0.5`). One
  software release supports many protocol versions; the numbers stay
  decoupled.

## Verification (implemented, with two blocked halves)

`wyrd-contracts` carries one named test per invariant direction
(catalog 23-33), over fixture stores checked in under
`tests/fixtures/stores/<release>/`. Two fixtures exist: the `dev`
harness-smoke store and the `v0.2.0-alpha` release baseline; per-release
fixtures continue under their tag with each release. (The `v0.1.0-alpha.1`
fixture went out with the reader-set format break: pre-v1 alphas may break
compatibility, and no legacy transition decoder is carried for
unshipped software. The v0.2.0-alpha release cut a fresh fixture and
re-enabled cross-release replay.) Two tests stay deliberately ignored
until their blockers land: fact-payload replay (invariant 2's
payload clause, pending the v0.9.0 payload-versioning issue)
and the full version matrix
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
