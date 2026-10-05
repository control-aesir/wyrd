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

- `write` only buffers; a snapshot is created by the DG-1
  commit-forcing events (`docs/write-path.md`, DG-1 table):
  dirty-handle `flush` or `release`, `fsync` on a path with pending
  data, and the other listed forcing events fold the whole pending
  set into one snapshot. An `fsync` on a path with no pending data
  anywhere performs no snapshot, and a clean, read, or
  never-wrote `flush`/`release` never forces on another handle's
  behalf, so idle closes are free for two independent reasons.
- `O_SYNC` / `O_DSYNC` never wait for a later boundary: each successful
  `write` is durable before returning, in its own durable snapshot
  shared with any pending set (`docs/write-path.md`, DG-1 table). This
  is the amplification peak, and it is opt-in per handle by the
  application.
- Each namespace operation addressed by **path** (`create`, `unlink`,
  `mkdir`, `rmdir`, `rename`, `chmod`, `truncate`) submits a mutation
  and commits one snapshot per *effective* operation — a truncate to
  the current size submits nothing, while a chmod to the mode already
  recorded commits no snapshot (the request still passes through the
  mutation loop, which evaluates it and returns `Done` without
  publishing).
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
| Repeated opens of unavailable content growing the fact log | Measured, no amplification. Workload (`unavailable_content_open_amplification_measurement`): 100 demands for never-local, never-arriving content through `set_materialization`, the engine-visible call every open's want admission funnels into, on a fresh engine. Result: 1 fact in 1 commit file, 0 retained-content bytes, 115 fact-log bytes, and 100 log rebuilds — one replay per demand, CPU with no IO. Fsyncs are 4 per commit, derived from the `DurableStore::commit_until` protocol sequence (commit temp, commits dir, CURRENT temp, drive dir), not counted; `one_commit_writes_one_commit_file` pins the one-commit-one-file premise the derivation rests on. Non-arrival does not change guard behaviour: the guards compare durable state, not reachability. If this row ever fails, G21 (`fact-log amplification`) owns the fix |

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
key and a tight loop. The refusal right is decided in the Retention
and refusal contract below (an authorization change, `trust.md` T18),
which names the bound, its two enforcement points, its refusal
semantics, and who bears the cost.

## Retention and refusal contract (decided, DG-4)

Open question 1 below is decided here; the question list keeps it as
the pointer. A serving member or a vault **may decline to admit what
an authorized member authored (A), or decline to serve, advertise,
or hold as residency what it already holds (B)**. The refusal right
is an authorization change (`trust.md` T18), not a resource limit:
membership implies the right to read, never the duty to retain.

The decision splits the old option 1 by enforcement point and takes
both halves. Every option as first stated was framed at the serving
boundary, which is the error this split corrects: a refusal taken at
the serving boundary happens **after** the bytes are already in the
append-only local store, so it bounds what a peer **promises**, not
what it **stores**. Physical bytes and provider residency are
different things — the store cannot un-hold bytes, so only a
pre-admission gate bounds disk, while only a residency refusal bounds
what the peer claims and serves. The two quantities need different
points, and they are one decision because neither works without the
other: a pre-admission gate is the only thing that bounds disk, and a
residency refusal with no admission gate behind it bounds nothing physical.

| | Quantity | Enforcement point | Bounds | Status |
|---|---|---|---|---|
| **A — storage admission** | bytes admitted to the local immutable store | at fetched-representation admission: the `Vault::import` calls in the `runtime/fetch/mod.rs` root, child, and object legs plus the snapshot-body import in the plan layer (`runtime/plan/mod.rs`), where an import failure is already a local refusal (`FetchOutcome::Local`), never a committed advertisement. Refused bytes are never stored by this device at all | disk | decided, unimplemented — the receive path is unbounded today |
| **B — provider residency** | objects/bytes held as *servable*, i.e. advertised as residency | two faces (see below): on the authoring device, after local durability before announcement (`write-path.md` steps 5–6: servable at 5, obligation discharged at 6); on a peer holding received content, at its own serving-mirror admission and serving maps. The bytes are already in this device's store — the refusal is about residency, not storage: durably accepted bytes the peer declines to make resident/servable under current local policy | what this peer promises | decided, unimplemented — today's mirror bounds are transient backpressure, not policy |

**B has two faces because only authors announce.** On the authoring
device the point is the steps 5–6 barrier: the announcement obligation
stays recorded and ineligible until serving residency is flushed, so a
residency refusal withholds discharge without touching the commit. A
peer holding received content has no step 6 to withhold — announcements
are the author's, and v0 has no replication serving
(`transport/routes.rs`: routes publish only from announcements'
`node_addr`). Its gate is its own mirror admission: the vault-to-mirror
write-through on `Vault::import`, and the boot rebuild, admit
only residency the ceiling allows, and the serving maps offer only
recorded-as-servable state (`VaultSource::from_state`: "Only recorded
state serves"). Obligations 1–2 are enforced there, not at an
announcement barrier the peer does not have. A B refusal at the mirror
gate is non-fatal to the fetch leg: unlike an import failure, it
neither aborts the leg nor rolls back the already-durable vault file —
only the serving record is withheld. The "charged" half holds where
the accountant sees the bytes, which today is the object leg alone
(only the plaintext insert charges `RetainedBytes`): body and manifest
bytes land in the vault retained but untallied, so the peer-side
ceiling cannot be evaluated on those legs until the counting gap is
closed, and no boot-time re-derivation can read them without the
durable refusal state the follow-up provides.

The gate covers the full structural closure the peer pulls — snapshot
body, root and child manifests, tree nodes — not only file-content
chunks: that closure is the amplification, and a chunk-only gate would
pass every acceptance criterion below while missing the adversary. On
the object leg the gate precedes both writes — the ciphertext import
and the plaintext object-store insert — since only the insert charges
the accountant, so refused bytes reach neither. Gate position decides
what is refused; what the ceiling can consult is decided by the
counter gap above.

The rejected options stay rejected for v0.3:

- **Eviction under pressure is refused.** Eviction creates a second
  question — "was this object merely locally evicted, or is this peer
  still a provider?" — which infects provider knowledge, repair,
  availability, pinning, and eventually GC. Accept-or-refuse has no
  such ambiguity, and eviction trades against the recovery property
  that motivates the append-only store.
- **Unbounded growth is refused as the contract.** Acceptable as an
  implementation policy for a trusted local store; not as the
  universal meaning of "peer" or "vault". A mitigation with a GC-tied
  expiry belongs to the GC design, not to this contract.

**The bound** is a per-device retained-byte ceiling: what is capped is
retained bytes on one device, at device granularity, and what it is
*not* is per-drive, per-member-set, or per-promise accounting — the
device scope is the conservative choice and the only one that needs no
membership state at the write boundary. The ceiling's number is
operational (like every budget in `resource-limits.md`); the *right*
to refuse at it is authorization (T18).

**Refusal semantics.** A retention refusal must never masquerade as
successful replication, and it cannot invalidate already-durable local
content. In particular B is not "received it and then lost it": it is
"durably accepted bytes this peer declines to make resident/servable
under current local policy." Three negative obligations, each needing
a negative test in the implementation follow-up:

1. A refused offer creates **no provider claim**: the refusing peer
   does not record, project, or report itself
   as a provider for that identity.
2. A refused offer satisfies **no serving request**: it must not
   appear as a route that resolves.
3. A refused offer advances **no announcement**: no announcement may
   carry a `node_addr` whose serving residency does not hold the
   announced representation — the barrier's existing job
   (`write-path.md` step 5; the `ServingBarrier` trait in
   `crates/wyrd-core/src/live.rs`), true of a refusal as of a slow
   mirror. The author's commit stands regardless: later-stage failure
   never rolls back earlier durable state, so refusing to
   retain or advertise does not un-commit the author's snapshot.

And the converse, which is the semantic invariant tying the other
three together and what makes the refusal safe to grant: a refusal
must also not *look* like content loss. "This peer did not
retain your object" and "your object is gone" are different statements,
and the operator surface must not conflate them, or the refusal right
becomes indistinguishable from corruption. After a refusal no other
node may infer "this provider had the content and subsequently lost
it": the refusing device's own state says, in effect, "this content
was refused for residency under local policy" — never damage, never
absence. Refused content therefore never enters loss/repair paths as
lost; retention policy cannot contaminate the existing loss semantics.
No refusal is reported as a transient fetch failure, a quiet absence,
or a successful replication.
There is no control-plane refusal signal in v0.3: a retention refusal
is a local policy outcome, not a peer-visible protocol event. A "peer
X declined your content" message is an enumeration channel and a
pressure surface, and building it in the milestone that grants the
right is backwards. Refusal is local and silent on the wire; the
operator reads it locally — the implementation reports the ceiling
that caused a refusal from `wyrd cache policy`, alongside the
reachable-content census and effective budgets it already shows.

**Who bears the cost.** The author bears its own disk (the local quota)
and its own fsync and announcement cost. The two halves split on what
the refuser already holds:

- A — nothing stored, nothing paid: refused bytes are never admitted,
  so the refuser's disk is untouched and the bytes are
  charged nowhere on it.
- B — stored and charged permanently, not advertised: the bytes are
  already in the refuser's append-only store with no GC to reclaim
  them, so they stay charged to its retained bytes; what the refuser
  does not bear is the residency — no mirror work, no promise, no
  serving. An implementer counts B-refused bytes
  as retained, not as absent.

In both halves the availability of refused content rests with the
author and the peers that did accept it — which is why the refusal can
never strand an author (the author's commit and obligation are intact)
nor censor a member (what a member is entitled to read stays readable
from a holder).

**Compatibility impact.** None on the persistent format and none on
the wire in v0.3: a refusal creates no durable `Fact` and no protocol
message, so drives written before this contract open unchanged and
peers that never refuse interoperate byte-for-byte with peers that do.
Ceilings default to unset (unlimited), so existing deployments behave
exactly as before until an operator opts in. The contract constrains
the follow-up's mechanism, not today's bytes.

**Interaction with the local quota.** The per-device
`retained_bytes_quota` and a serving-boundary ceiling are different
ceilings and must not be conflated in `wyrd cache policy`'s output: the
quota bounds the author's own commits before their first write
(`LiveNode::enforce_retained_quota`, ahead of every arm of
`apply_mutation` in `crates/wyrd-core/src/live.rs`); the refusal
ceilings bound what a device accepts from others and what it promises
to serve. Until the receive path enforces A, the interference channel
stands as documented: a remote author can spend a peer's local-write
headroom by authoring content, because fetched bytes charge the
accountant with no ceiling in scope.

**Prerequisite, not follow-up.** `RetainedBytes`
(`crates/wyrd-format/src/store.rs`) has `add` and `get` and no
decrement. Once A is enforced that is a correctness bug — a scrubbed
or quarantined object keeps its charge forever, so the store would
eventually refuse everything it is offered. A decrement, or an
authoritative recomputation, lands with A's enforcement, not after it.
B carries two prerequisites of its own, alongside A's decrement: a
counter that sees vault bytes — beside the mirror accounting in
`wyrd-sync`, where ciphertext already lives, rather than as a widened
`wyrd-format` `RetainedBytes`, which the plaintext-world split reserves
for plaintext accounting; the follow-up confirms the home — since body
and manifests are retained but untallied today, so the peer-side ceiling
has nothing to consult on those legs; and durable refusal state the
boot rebuild can consult (the rebuild cannot distinguish "refused for
residency" from "never seen" without it).

**Acceptance criteria** (for the implementation follow-up, which this
contract unblocks rather than contains):

- `a_serving_refusal_creates_no_provider_claim`: at its ceiling, a
  peer declines an offer; no route resolves, no status output names it
  a provider, no announcement carries a dialable address for it. On a
  peer holding received content, the refused representation additionally
  never reaches its serving mirror or its serving maps.
- `a_serving_refusal_leaves_the_author_commit_intact`: the author's
  snapshot is durable, its heads advanced, its outbox discharged —
  steps 1–4 and 6 unaffected.
- `a_serving_refusal_never_advances_an_announcement`: with the
  barrier installed and residency refused, the obligation stays
  recorded and ineligible — the ceiling case of the backpressure shape
  `a_full_mirror_queue_applies_backpressure_without_losing_the_vault`
  already pins.
- `a_refusal_is_not_reported_as_content_loss`: the operator surface
  distinguishes "declined at the ceiling" from "unavailable" and from
  "corrupt", and the refusing device records the refusal as local
  policy — refused content never enters loss/repair paths as lost.
- The local-quota interaction: a device with both ceilings reports two
  distinct numbers, and the local ceiling's handle semantics (buffer
  lost, `EIO` thereafter) are unchanged.
- `wyrd cache policy` shows the ceiling that caused a refusal.

**Dependents unblocked.** The control-message reconciliation decision
takes its requirements against this model without waiting for the
accounting implementation; what a vault role promises is downstream of
it; the retention accounting itself (open question 2) is downstream
implementation, Ring 3.

## Pre-GC bounds: what could be enforced

One bound here is implemented: the per-device retained-bytes quota. Two
more are decided but not yet enforced (the A and B refusal ceilings
above). The rest are the record of which candidates were screened out,
so the GC design starts from a settled list rather than re-testing
rejected options.

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
  retention refusal right above, wearing a different name. It inherits
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

The quota is narrower than "a ceiling on storage" in three ways, and each
one is a place where the number understates what the device holds. The
fourth thing below is not that: it is what running into the ceiling costs,
which is a different question and the one an operator meets first.

Three terms keep those questions separate, because one counter
previously served both jobs. **Retained bytes** is the enforcement
quantity: what the object store holds and the ceiling is compared
against. **Resident bytes** is what the device physically holds:
retained bytes plus everything else on its disk. **Auxiliary growth**
is the resident-but-unenforced durable state — the fact log and the
sync vault — reported next to the enforced number, never folded into
it. `wyrd cache policy` renders all three with their labels; a quota
is an operator-selected refusal boundary over retained bytes, not an
implicit product policy over the device.

**Only the mounted write path refuses.** The check sits in the live
node's commit boundary, ahead of every arm of `apply_mutation`. Four
writers raise the count with nothing to refuse them: the sync pass
fetching objects into the same store, the vault retaining ciphertext per
representation, the fact log growing per commit / per accepted intake
message / per delivery, and the node's own `put_file` and `remove`, which
insert chunks and tree nodes and author a snapshot with no quota in scope.
(The fact log is not unbounded by a pass — materialization commits are
idempotent, as "Already bounded" records — it simply is not metered here.)

That last one is the narrowest and the most likely to be assumed covered,
because those methods sit on the same type that carries the accountant.
But `into_live` consumes the node, so it is the pre-live and
headless-embedder window rather than a hole in the mounted path. Either
way the device's retained bytes are *not* bounded by the configured
number, and the number can be crossed by paths that
have no ceiling at all.

**And that makes it an interference channel.** Because those unrefused paths
do charge the accountant, a remote author can spend a peer's headroom
simply by authoring content — the peer accepts the closure, its count
climbs past the quota, and the first refusal lands on the peer's own next
local write as `ENOSPC`. Nothing is deleted and no logical state changes;
the drive looks healthy while the local author is locked out of writing.
This is a consequence of *this* bound rather than a pre-existing
property, and it is the strongest practical argument for open question 1:
until peers have a refusal right, a local quota is a lever a remote member
can pull.

**The overshoot is bounded by the tree nodes.** The fold gate compares bytes
already retained plus a conservative estimate of the pending set's new
retention — full image lengths, while dedup and chunking only reduce
what the store keeps — before the commit's first write
(`docs/write-path.md`, rule 6). An admitted fold satisfies
count + estimate < quota, so it lands strictly *below* the quota by the
estimate's over-count margin; the only way back over is the rebuilt
tree nodes the estimate deliberately omits (below its precision, by
design). The estimate covers the handle's buffered image — up to 64 MiB
of write buffer (`MAX_WRITE_BUFFER_BYTES`) — while the tree nodes
rebuilt on the changed path are the separate step-1 row in the
fixed-cost table above and do not scale with the write. On the fetch
path nothing bounds `N` at all. A commit is refused when count plus
estimate is already over — which, because the estimate over-counts,
includes rewrites that would retain nothing new.

**And it is one-way absent a removal path.** Nothing lowers the count
except a durable removal bookkept through `RetainedBytes::subtract`:
no GC, no eviction, and bytes charged by a fetch or by a commit that
failed after its inserts stay charged until a removal path (quarantine,
scrub) takes them and subtracts them. Reclassifying resident bytes —
moving them, unpinning them, ceasing to serve them — without removing
them must not subtract; quarantine is a decrement only where quarantine
actually removes bytes from the retained set. A quota set at or below
current retention therefore leaves the device permanently unable to
take a local write, and raising the quota is the only remedy short of
a removal — and the refusal set is wider than that sentence: the fold
gate refuses at count plus full image lengths, so a quota within one
image length *above* retention still refuses content writes. At the
ceiling every local mutation is refused, including
ones that would retain nothing new — unlike a real full disk, where a
zero-byte write still succeeds. A device back under its ceiling by way
of a removal accepts writes again — with room for the fold estimate,
not just the count: a rewrite needs count plus its full image length
to fit, even when dedup means it retains nothing.

**A refusal costs the open handle its buffer.** The commit takes the
handle's buffered image before submitting, so an `ENOSPC` at `fsync`
discards those uncommitted bytes and every later operation on that
descriptor returns `EIO`. A program that writes and `close`s without an
explicit sync gets no errno at all — `release` commits best-effort, logs,
and returns success — so that path loses the write silently. This is
master's policy for every commit failure and exactly what a genuinely
full disk does, which is the sense in which a quota is a smaller disk and
not a weaker promise. It is stated here because an operator deciding
whether to set a ceiling should know that running into it costs open
handles, not just the write in hand.

## Open questions

1. **Do serving members and vaults get a retention refusal right?**
   **Decided: yes** — see the Retention and refusal contract above,
   and `trust.md` T18 for the authorization half. The contract splits
   the old option 1 by enforcement point and takes both halves (A:
   pre-admission gate on the receive path; B: provider-residency
   refusal after durability, before announcement); eviction under
   pressure and unbounded-growth-as-contract are refused for v0.3.
   What remains is implementation: neither ceiling is enforced yet.
   The accounting machinery for it is in place — `RetainedBytes::subtract`
   exists for the removal paths (quarantine, scrub) with the
   durable-removal-only discipline, `check_retained_ceiling` diagnoses a
   quota below current retention at startup, and `wyrd cache policy`
   reports retained / fact-log / vault bytes separately — but no
   removal, admission-gate, or residency-refusal caller exists yet.
   The question entry stays as the pointer; the contract is the answer.
2. **Quota accounting still open.** The quota's refusal point shipped as
   decided above: before the commit's first write to disk, so a refused
   commit retains nothing. What the implementation leaves open, and
   what a follow-up should settle:
    - **Counting the other two writers.** Settled as report, not as
      enforcement (OD-26-B option B). `RetainedBytes` still covers the
      object store only — widening it would silently widen what a
      refusal rejects — and `wyrd cache policy` reports the fact log
      and the sync vault as separate observational rows with an
      observational total, each labelled, so the gap is explicit
      instead of a single total known to be low.
    - **Refusing the unrefused paths.** Fetched objects cross the quota
      with no ceiling in scope, which is what turns a local quota into the
      interference channel above. Whether a peer may decline to retain is
      decided in the contract above (open question 1, `trust.md` T18):
      the fetch-side refusal is local policy at the admission points
      named there, not a new protocol surface — there is no wire refusal
      signal in v0.3 — and until it is enforced the interference stands
      as documented, leaving the quota to local-write protection only.
    - **In-flight accounting.** Documented, not implemented. The fold
      gate compares bytes already retained plus a conservative
      estimate of the pending set (full image lengths), so the
      effective ceiling is the quota plus the admitted fold's rebuilt
      tree nodes — the only bytes that can carry the count over, since
      the fold lands strictly below quota by the estimate's margin.
      Up-front reservation in the strict sense would require predicting
      exact retention before step 1 runs; the estimate is the
      prediction, deliberately over-counting. The overshoot bound is
      pinned by `a_removal_below_the_ceiling_readmits_local_writes`
      (at-ceiling refusal, then admission, overshoot past quota by
      tree bytes, and refusal again).
    - **A startup cross-check.** Settled, with a stated boundary.
      `check_retained_ceiling` (`wyrd-core`) compares a configured quota
      against `FsObjectStore::retained_bytes` — one walk at open, never
      per commit — before the node starts, so a quota below current
      retention is one named diagnosis with both numbers instead of a
      stream of `ENOSPC` at the first write. Both binary composers
      (`mount` and `sync_now`) call it through one shared helper.
      The diagnosis covers `retained > quota` only: a quota within one
      image length above retention passes the check yet refuses content
      writes at the fold gate. Widening it belongs to a configuration
      surface. Pinned by
      `a_quota_below_current_retention_is_diagnosed_at_start`.
    - **Granularity.** The bound is per device. Per drive would bound the
      *author* across its devices; per member-set would bound a group.
      The device scope is the conservative choice and is the only one
      that needs no membership state at the write boundary.

Tracked by the two follow-ups raised with this document:
`protocol(storage): decide whether peers and vaults get a retention
refusal right` (open question 1, now decided by the contract above;
its enforcement is the implementation follow-up) and `feat(storage):
per-device retained-bytes quota at the commit durability boundary`
(open question 2). The quota issue's title predates the refusal point
being settled above and names the durability boundary; the title is not
the decision —
read that issue together with this section before implementing it.
