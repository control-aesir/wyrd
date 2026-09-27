# Storage growth and the retention bound

`resource-limits.md` is the normative document for bounds the daemon
enforces. This one states the resource none of them can cap — how much
the store **retains** over time — and specifies the one bound that
survives the append-only store, together with what it does not cover. A
later GC design should start here, so this document's job is to give it a
defined adversary rather than an open assumption.

The per-device retained-bytes quota and the two "Already bounded" rows
are enforced current behavior, each with the code that closes it. The
rest is analysis and screening, not code. Read the quota's limits below
before treating it as a ceiling on disk: it is a ceiling on one write
path, not on the device.

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
score that device at zero. The substitution is exact for the **fixed**
term. For the content term on a replica it deliberately
over-approximates, since chunks land only when a want pulls them; the
inequality still holds and erring high is the safe direction for a
ceiling.

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
| Fact-log append + `CURRENT` rewrite | authoring / durability | both | both |
| Durability fsyncs | durability | both | both |
| Announcement obligation recorded, then discharged | authoring / announcement | author | author only — both halves are driven from the author's own durable outbox, and the per-recipient factor (delivered markers, byte-identical sealed retries per route) is likewise author-side, so this term scales with recipient count and is not a per-commit constant |
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
- Each namespace operation addressed by **path** (`create`, `unlink`,
  `mkdir`, `rmdir`, `rename`, `chmod`, `truncate`) submits a mutation
  and commits one snapshot per *effective* operation — a truncate to
  the current size, or a chmod to the mode already recorded, submits
  nothing.
- The same operations addressed through a **file handle** (`ftruncate`,
  `fchmod`) are not always immediate: on a writable, non-append handle
  they arrive as the same `setattr` carrying a `FileHandle`, resize or
  re-flag the buffered image, mark the handle dirty, and commit only
  under `O_SYNC`, so `write` + `ftruncate` on one handle is one
  snapshot, not two. On an **append** handle (`O_APPEND`, the default
  for `>>`) and on a **read** handle a *mode* change is
  path-addressed and submits immediately; a *size* change through
  those handles is refused outright (`EOPNOTSUPP` on append, which has
  no full image to truncate, and `EBADF` on read), so neither can be
  used for handle-addressed churn.

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
| Serving member / peer | the whole structural closure per accepted announcement — snapshot body, root and child manifests, tree nodes — whether or not a want asked for it; **chunk** objects only when a want pulls them | no — paced per pass by the fetch pass budget, per object by the ingest ceilings, but unbounded in retention |
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

One bound here is implemented: the per-device retained-bytes quota. The
rest are the record of which candidates were screened out, so the GC
design starts from a settled list rather than re-testing rejected
options.

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
| Per-device retained-bytes quota | Refuse the commit before its first write to disk, reporting `ENOSPC` | `ENOSPC` from `flush`/`fsync` is already a legitimate reportable outcome, and quota-full already classifies as `StoreFailure::StorageFull` → `ENOSPC` for mount writes (see `resource-limits.md`, Disk classification). A quota is a smaller disk, not a weaker promise. Implemented: `ResourceBudgets::retained_bytes_quota` (default `None`, unlimited), enforced by `LiveNode::enforce_retained_quota` ahead of every arm of `apply_mutation`, counted by `wyrd_format::RetainedBytes` |

The refusal point is load-bearing and easy to get wrong, in the one
place where being off by a step is the failure mode being designed
against. Two boundaries matter, and they answer different questions.

**The byte ceiling** must be checked before the commit's **first** write
to disk — which is the object insert, not the seal. A mutation writes
its chunks and rebuilt tree nodes into the object store and only then
reaches authoring, in the same call, with no decision point in between.
A check placed anywhere later has already spent the bytes it is trying
to protect, and with no GC those objects are unreferenced and
unreclaimable. The leak is not a constant, because the member chooses
its size: one handle's buffered image is capped at 64 MiB
(`MAX_WRITE_BUFFER_BYTES`), so a single commit inserts up to that much
in chunks — at 16 KiB minimum chunk size, up to 4,096 chunks, and at
the 256 KiB maximum chunk size only 256. (The 65,536-chunk
`Limits::V0` ceiling is reachable on a *replica's* fetch path, which is
the other bearer, not this one.) Writing one large new file inserts
every chunk and is then refused, on every attempt, at no cost in quota.
A quota that allowed that would not be a ceiling.

**The fact-commit** — the single call that ends authoring, writing the
snapshot-body, manifest, and `AnnouncementQueued` facts together — is
the *latest still-consistent* point, because a refusal after it strands
a durable announcement obligation for a snapshot that does not exist.
Refusing there strands no facts either, which is what makes it the
latest consistent choice, but by then the commit's bytes are already
spent, which is why it is not the byte ceiling's point.

The quota bounds the author's own device and converts a silent unbounded
growth into an explicit, documented, POSIX-legitimate refusal. It does
not bound the author **on other devices, nor in the vault**: a member's
commits are valid work, and GC is the only mechanism that can make old
bytes stop existing. That is open question 1, and it is a `trust.md`
authorization change rather than a resource limit.

The quota is narrower than "a ceiling on storage" in four ways, and each
one is a place where the number understates what the device holds.

**Only the local write path refuses.** The check sits in the mounted
commit boundary. The sync pass writes fetched objects into the same store
with no quota in scope, the vault retains ciphertext per representation,
and the loop commits facts every pass. All three raise the count; none
of them is ever refused. So the device's retained bytes are *not* bounded
by the configured number, and the number can be crossed by paths that
have no ceiling at all.

**Which makes it an interference channel.** Because those unrefused paths
do charge the accountant, a remote author can spend a peer's headroom
simply by authoring content — the peer accepts the closure, its count
climbs past the quota, and the first refusal lands on the peer's own next
local write as `ENOSPC`. Nothing is deleted and no logical state changes;
the drive looks healthy while the local author is locked out of writing.
This is a consequence of *this* bound rather than a pre-existing
property, and it is the strongest practical argument for open question 1:
until peers have a refusal right, a local quota is a lever a remote member
can pull.

**The overshoot is one whole commit.** The check compares bytes already
retained, so a commit that starts one byte under the quota is admitted
and can take the total to `quota + N` for whatever that commit retains. On
the author path `N` is bounded by the write buffer, 64 MiB
(`MAX_WRITE_BUFFER_BYTES`); on the fetch path nothing bounds it. No commit
is ever refused *for crossing* the ceiling — only once it is already over.

**And it is one-way.** Nothing lowers the count: no GC, no eviction, and
bytes charged by a fetch or by a commit that failed after its inserts stay
charged forever. A quota set at or below current retention therefore
leaves the device permanently unable to take a local write, and raising
the quota is the only remedy. At the ceiling every local mutation is
refused, including ones that would retain nothing new — unlike a real full
disk, where a zero-byte write still succeeds.

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
2. **Quota accounting still open.** The refusal point shipped as
   decided above: before the commit's first write to disk, so a refused
   commit retains nothing. What the implementation leaves open, and
   what a follow-up should settle:
   - **Counting the other two writers.** `RetainedBytes` covers the
     object store only. The sync vault retains ciphertext per
     representation, and the fact log grows with every pass; both are
     writers the tally never sees, so the reported total is lower than
     the bytes this device actually holds.
   - **Refusing the unrefused paths.** Fetched objects cross the quota
     with no ceiling in scope, which is what turns a local quota into the
     interference channel above. Whether a peer may decline to retain is
     open question 1 and a `trust.md` decision; until it is made, the
     honest options are a fetch-side refusal (new protocol surface) or
     documenting the interference and leaving the quota to local-write
     protection only.
   - **In-flight accounting.** The check compares bytes already
     retained, so the effective ceiling is the quota plus whatever the
     next admitted commit retains. A stricter reading would reserve the
     in-flight delta up front.
   - **A startup cross-check.** `MemoryObjectStore::retained_bytes` is
     the composition root's cross-check and nothing calls it yet, so a
     quota set below current retention is discovered as a stream of
     `ENOSPC` at the first write rather than as a startup diagnosis.
   - **Granularity.** The bound is per device. Per drive would bound the
     *author* across its devices; per member-set would bound a group.
     The device scope is the conservative choice and is the only one
     that needs no membership state at the write boundary.

Tracked by the two follow-ups raised with this document:
`protocol(storage): decide whether peers and vaults get a retention
refusal right` (open question 1) and `feat(storage): per-device
retained-bytes quota at the commit durability boundary` (open question
2). The quota issue's title predates the refusal point being settled
above and names the durability boundary; the title is not the decision —
read that issue together with this section before implementing it.
