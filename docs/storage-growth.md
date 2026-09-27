# Storage growth and the retention bound

Analysis, not an enforced bound. `resource-limits.md` is the normative
document for bounds the daemon enforces; this one states the resource
none of them can cap — how much the store **retains** over time — and
screens which bounds could be enforced before GC exists. A later GC
design should start here, so this document's job is to give it a defined
adversary rather than an open assumption.

Within this document, the fixed-overhead table and the two "Already
bounded" rows describe enforced current behavior, each with the code
that closes it. Everything else is analysis, screening, or a proposal.
The per-device quota is a proposal, not code.

## Why retention is separate

Every bound in `resource-limits.md` is a *live-process* bound: it caps
one operation, one pass, or one set of open handles, and each is
released when the operation ends. None of them caps retention. The
store is append-only with no GC in v0 (`AGENTS.md` hard rule; see also
`crash-consistency.md`, unreferenced objects are never reclaimed), so
committed bytes are never reclaimed: a bound that refuses the thousandth
concurrent write is irrelevant to a member who commits serially
forever. Retention is the one resource that escapes those bounds in a
way that *amplifies*.

(The append-only membership log is also unbounded in depth — by
design, no depth cap — but it is owner-gated and grows per membership
transition rather than per authored byte, so it is not an amplification
path.)

## The bound, stated

The counting variable is **per retaining device**, not per authoring
seat: a replica that authors nothing still retains what it is sent.

> retained bytes <= (snapshots retained) x (per-snapshot fixed
> overhead + content-proportional bytes)
>
> where snapshots retained = locally authored + accepted from peers

*Accepted*, not *materialized*, and the distinction is load-bearing:
materialization is content residency (`RemoteOnly | Cached | Pinned`),
so a device that accepts announcements and lets their structural
closures land but never wants a byte of file content still pays the
full structural cost — and counting only materialized snapshots would
score that device at zero.

On the author's own device the term is set by its own commit rate. On a
replica it is set by **its peers'** commit rate, which is the whole
reason the author is not the only bearer. The fixed overhead is also
per *recipient* for the announcement leg, so a member with N devices
pays that term N times per snapshot.

The **fixed** term is the architectural problem. It does not shrink
with change size, it is not reduced by content-addressed chunking or
copy-on-write trees, and it dominates for small writes. Optimizing the
per-commit cost (`seal_tree`, chunking) cannot bound it; only reducing
the *number* of commits can, which is the mutation-unit question in
`write-path.md`, not a micro-optimization.

## Per-snapshot fixed overhead

Produced-by and retained-by are different questions, and conflating
them understates the adversary. The **Produced by** column says which
seat generates the bytes; a replica retains the authored-by-others form
of the author-side rows, because the structural closure is pulled for
every announcement it accepts (see "Who bears the cost").

| Fixed cost | Step | Produced by | Retained by |
|---|---|---|---|
| Rebuilt tree nodes for the mutation | objects | author | author **and replica** — the plan treats tree nodes as structural: "the closure cannot be navigated or verified without them, so they are always wanted" |
| Signed snapshot body | authoring | author | author **and replica** — the body is signed by the author and imported into the replica's own vault; a replica verifies the signature, it does not produce one |
| Sealed root and child manifests, imported | authoring | author | author **and replica** — every held manifest's children are planned, not just a want's |
| Fact-log append + `CURRENT` rewrite | durability | both | both |
| Durability fsyncs | durability | both | both |
| Announcement obligation recorded, then discharged | durability / announcement | author | author only — both halves are driven from the author's own durable outbox, and the per-recipient factor (delivered markers, byte-identical sealed retries per route) is likewise author-side, so this term scales with recipient count and is not a per-commit constant |
| Serving mirror write-through + flush barrier | serving | both | both |
| Projection generation bump + head swap | publication | both | both |

A GC designer sizing an **authoring device** uses the whole table. Sizing
a **replica** means counting every row except the announcement
obligation — the two largest terms, the tree nodes and the manifests,
are retained by a replica precisely because they are structural. Omitting
them would price a peer's disk at roughly a third of its real cost.

The re-seal of the root manifest is new bytes on every commit, and the
reason is load-bearing: the manifest's own `ContentId` is derived from
plaintext and the vault's `import` is a no-op for a root it already
holds, so content-addressing alone *would* dedupe an unchanged re-seal.
What defeats it is that `seal` draws a fresh 24-byte random nonce, so
each seal is a distinct envelope with a distinct transport root over the
sealed bytes — and that root is the vault's address.

The fsync count is the term that actually costs wall-clock: the
durability boundary makes several stores durable *together*, and a
first-write hierarchy syncs its directories level by level.

The serving-mirror term is bounded by queue depth
(`MAX_MIRROR_QUEUE_ITEMS` 64, `MAX_MIRROR_QUEUE_BYTES` 64 MiB) — a
depth bound, not a per-pass one: exceeding it fails the import with
`VaultError::MirrorFull` rather than deferring.

## Content-proportional bytes

Small because a mutation materializes only what it touches: a commit
rebuilds the affected tree nodes and the file's chunk list, and reuses
unchanged nodes, chunk objects, and recorded representations (including
manifest mappings, where the epoch rules allow). A one-byte edit to a
large file does not copy the file.

Each *object* is separately capped by `Limits::V0`
(`wyrd-sync/src/ingest.rs`): 64 MiB per object pre-decode, 256 KiB
chunk payloads (plus the 6-byte envelope header), 65,536 chunks per
file, 1M tree entries, 580K manifest entries, 1M manifest children.
These are per-object ceilings, so they bound the content term of any
single snapshot and nothing about how many snapshots exist.

## What drives the snapshot count

No debounce or autosave timer exists in the code. Snapshots are created
by POSIX boundaries on the authoring device:

- `write` only buffers; a snapshot is created by `flush`, `fsync`, or
  `release` on a dirty handle. A committing boundary on a **clean**
  handle performs no snapshot, so idle flushes are free.
- `O_SYNC` / `O_DSYNC` deliberately forfeit coalescing: each successful
  `write` is its own durable snapshot. This is the amplification peak,
  and it is opt-in per handle by the application.
- Each namespace operation (`create`, `unlink`, `mkdir`, `rmdir`,
  `rename`, path-addressed `truncate`, `set-exec`) submits a mutation
  and commits one snapshot each.
- A **handle** `truncate` does not: it arrives as `setattr` on an open
  file, resizes the buffered image, and marks the handle dirty, so it
  joins that handle's next boundary commit. `write` + `ftruncate` on one
  handle is therefore one snapshot, not two.

So the rate is chosen by the member, at their own throughput, and is not
throttled by any protocol timer. On a replica the corresponding rate is
its peers'.

The cheapest attack is therefore not `write 1 byte, commit, repeat` — it
is **pure namespace churn**, `unlink` + `create` on one path, in a loop.
That is two snapshots per iteration while writing **zero file-content
bytes**, so the file-content term drops out. What does not drop out is
everything else the commit costs: a rebuilt root tree node, a freshly
sealed root manifest, a signature, a fact-log commit, the durability
fsyncs, and a full announcement set. The bound's remaining term is
therefore the fixed term in full, multiplied without limit.

## Already bounded (writer-side amplification)

Both writer-side paths named in the storage-bound discussion are closed.
These two rows describe enforced behavior, not screening:

| Path | Bound |
|---|---|
| Repeated failed wants appending unchanged `Fact::Materialization` | Closed. `Engine::set_materialization` / `set_materialization_from` compare durable state first and append nothing when it already equals the target, so a retried want costs no fact and no fsync. Both append sites are guarded (`runtime/engine/mod.rs`), pinned by `repeat_materialization_admission_commits_nothing` — a ten-deep retry storm commits nothing, and a genuine transition commits exactly once |
| Unbounded serving-mirror import queue | Closed. `MAX_MIRROR_QUEUE_ITEMS` (64) and `MAX_MIRROR_QUEUE_BYTES` (64 MiB) in `serving.rs`; a full queue returns `VaultError::MirrorFull` and keeps the vault file durable. Pinned by `a_full_mirror_queue_applies_backpressure_without_losing_the_vault` and `an_oversize_reservation_fails_before_queueing` |

The remaining growth is the commit path itself: bounded per commit,
unbounded in count.

## Who bears the cost

| Party | Bears | Bounded today |
|---|---|---|
| Author | local disk, and its own fsync and announcement cost | yes, per operation |
| Serving member / peer | the whole structural closure per accepted announcement — snapshot body, root and child manifests, tree nodes — whether or not a want asked for it; **chunk** objects only when a want pulls them | no — paced per pass under the admission and ingest ceilings, but unbounded in retention |
| Vault | retained ciphertext per representation, and the count of them | no |

The asymmetry is the finding, and the eager structural pull sharpens it.
Intake commits transition / announcement / capability / control-message
facts and never opens manifests, trees, or chunks, so one might expect a
peer to hold only *history*. It holds more than that: reconciliation
plans the root for every announcement, plans child manifests from every
held manifest's children rather than from a want, and treats tree nodes
as structural because the closure cannot be navigated without them. The
plan runs every pass with no want gate. So a peer pays for the shape of
what a member did whether or not it ever wants a byte of the content —
only file content is genuinely pull-based.

Authorization in v0 is membership, and membership carries **no retention
obligation and no refusal right**: `trust.md` records that object
admission is content verification with no per-object ACLs, and
availability is explicitly called out as "not a confidentiality break" —
but nothing lets a peer or vault decline to retain what an authorized
member authored. One member can force unbounded growth on every other
member and on every vault, at a cost to the attacker that is one signing
key and a tight loop. Adding a peer refusal right would change the
authorization contract, so it is recorded as an open question below
rather than decided here.

## Pre-GC bounds: what could be enforced

**Nothing in this subsection is implemented.** It records which bounds
survive the durability contract, so the GC design starts from a screened
list rather than re-testing rejected options.

Enforcement must not contradict the durability contract. Three of the
obvious candidates fail that test, and the fourth is deferred:

- **Snapshot rate limiting is not available pre-GC.** `flush` and
  `fsync` are semantically equivalent and the commit boundary *is* the
  durability boundary (`write-path.md`); a rate limit would have to
  either delay or fail a call that POSIX says is already durable, and
  `O_SYNC` promises one durable snapshot per write. Delaying a
  reported-durable commit is a correctness regression, not a bound.
- **History-depth policy cannot be enforced without GC**, because there
  is nothing to prune when the policy is exceeded; it can only be
  observed and reported.
- **Vault pinning limits are not screened separately**, because any form
  of them — a cap on what a vault will hold for one drive — *is* the
  retention refusal right below, wearing a different name. It inherits
  that decision rather than pre-empting it.

One candidate survives, and it is the only pre-GC bound that reuses an
existing error path unchanged:

| Bound | Enforcement | Why it is safe |
|---|---|---|
| Per-device retained-bytes quota (proposed) | Refuse the commit before the authoring step's first write to disk, reporting `ENOSPC` | `ENOSPC` from `flush`/`fsync` is already a legitimate reportable outcome, and quota-full already classifies as `StoreFailure::StorageFull` → `ENOSPC` for mount writes (see `resource-limits.md`, Disk classification). A quota is a smaller disk, not a weaker promise |

The refusal point is load-bearing and easy to get wrong, in the one place
where being off by a step is the failure mode being designed against. The
objects and the sealed envelopes are each written with temp + fsync +
rename + directory fsync *before* any commit decision exists, so a quota
checked at the durability boundary refuses *after* spending the bytes it
was trying to protect: the effective ceiling becomes quota + one commit,
and every refused attempt permanently spends budget, because with no GC
those objects are unreclaimable.

The boundary to check against is therefore the single fact-commit that
ends authoring, where the snapshot-body, manifest, and
`AnnouncementQueued` facts are written together — not the durability
boundary. Refusing before that one call strands nothing; refusing after
it strands the obligation for a snapshot that does not exist.

A quota would bound the author's own device and convert a silent
unbounded growth into an explicit, documented, POSIX-legitimate refusal.
It would not bound the author **on other devices, nor in the vault**.
Nothing in v0 can bound the author, because a member's commits are valid
work and GC is the only mechanism that can make old bytes stop existing.

## Open questions

1. **Do serving members and vaults get a retention refusal right?**
   This is the only pre-GC bound that limits the *author*, and it is a
   `trust.md` authorization change, not a resource-limit change:
   membership currently implies unbounded retention. The eager
   structural pull is what makes this sharp — a peer cannot opt out of
   retaining the manifests and tree nodes of every announcement it
   accepts, and it has no way to express "materialize the content but
   not the shape". Options are a per-drive byte ceiling with `ENOSPC` at
   the serving boundary, an eviction-under-pressure rule (which trades
   against the recovery property that motivates the append-only store),
   or accepting unbounded peer growth until GC. Not decided here.
2. **Quota granularity and check sequencing**: per device, per drive, or
   per member-set, and how the check interleaves with a commit already
   in flight. The refusal point is settled above (before the authoring
   step's first write to disk); what stays open is the accounting for a
   commit that is already underway when the quota is crossed, and the
   interaction with the announcement obligation, whose facts share that
   final fact-commit — so a refusal must land before it and leave no
   durable obligation behind.

Tracked by the two follow-ups raised with this document:
`protocol(storage): decide whether peers and vaults get a retention
refusal right` (open question 1) and `feat(storage): per-device
retained-bytes quota at the commit durability boundary` (open question
2). The quota issue's title predates the refusal point being settled
above and names the durability boundary; the title is not the decision —
read that issue together with this section before implementing it.
