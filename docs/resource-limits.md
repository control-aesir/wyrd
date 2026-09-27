# Runtime resource limits

Normative bounds for live operation: which finite resources the daemon
budgets, what happens at each bound, and how exhaustion surfaces. The
protocol ingest ceilings (`Limits::V0`, bounding every committed
object) are not in scope here — they bound committed data, while this
doc bounds the live process holding and moving it.

Those bounds are per operation. Exactly one resource escapes all of
them — how much is *retained* over time, which no live bound can cap
under an append-only store. That bound, its adversary, and what is
enforceable before GC are in [Cumulative storage growth](#cumulative-storage-growth).

All bounds live in one struct, [`ResourceBudgets`](../crates/wyrd-core/src/budgets.rs),
threaded from `LiveConfig` into the loop, the registries, and the
backend at composition time. Defaults are the historical hardcoded
bounds — with four intentional new ones: the per-pass admission cap
(admission was previously uncapped per pass), the open-handle cap
(the table previously relied on the kernel descriptor limit alone),
the open-capture byte ceiling (the count cap could not bound
retained chunk-list bytes), and the parent-token retention cap for
the create-parent registry.
4096 handles is far above plausible interactive use (tens of open
descriptors) while bounding handle count, so it does not
regress supported workloads. Retained capture bytes have their own
256 MiB ceiling alongside it: one maxed-out file (65,536 chunk
identities, 2 MiB per read capture) still opens, the 129th
concurrent one fails closed instead of retaining gigabytes.
`ResourceBudgets::default()` is the
pinned contract for the legacy defaults. Tuning is library-level:
the `wyrd` binary takes no flags for these today and runs defaults.

## Bounds

| Boundary | Bound (default) | Past it |
|---|---|---|
| Want registry identities (pending + admitted) | `max_pending_wants` (4096) | registration fails; `EIO` at the POSIX boundary, never a silent drop |
| Want admission per sync pass | `max_admit_per_pass` (1024) | remainder stays pending for the next pass — paced, never dropped |
| Mutation queue (admitted-but-incomplete) | `max_pending_mutations` (4096) | submission fails `Saturated`; `EAGAIN` |
| Parent create tokens (distinct retained paths) | `max_parent_tokens` (4096) | new parent capture fails closed; `ESTALE` at the FUSE boundary |
| Write buffer per dirty handle | `write_per_handle_bytes` (64 MiB) | reservation refused; `ENOSPC`, handle unchanged |
| Write buffers aggregate | `write_aggregate_bytes` (256 MiB) | reservation refused; `ENOSPC` |
| Dirty (buffered) handles | `write_dirty_handles` (64) | new dirty handle refused; `ENOSPC` |
| Open file handles (read + write) | `max_open_handles` (4096) | open refused; `EMFILE` |
| Open-capture bytes aggregate (read chunk lists + writable capture-plus-base) | `max_open_capture_bytes` (256 MiB) | open refused; `ENOSPC`. Checked at open; a handle's retention may grow toward the ingest chunk ceiling afterwards |
| Mailbox relay wire message | 512 KiB normalized JSON (SDK) | SDK transport backstop before the parsed event reaches Wyrd |
| Mailbox relay event | 256 KiB decoded event-payload estimate (const; content plus tag values, after SDK parsing) | rejected before NIP-59 unwrap; the relay retains it for redelivery |
| Mailbox notification channel | 1024 events (const) | backpressure stalls the relay stream; the relay retains everything |
| Mailbox held handovers | 1024 unacked (const) | `recv` stops pulling; held mail rotates so the engine drains free |
| Engine intake held messages | `MAX_PENDING_MESSAGES` 1024 (const) | over-limit deferrals shed without consuming; relay redelivers |

The mailbox and engine-intake bounds stay constants: they are
protocol-adjacent, already bounded and backpressure-tested, and not
operational tuning. The daemon-side bounds above are the configurable
ones.

## Intake computational budgets

Byte ceilings alone do not bound CPU: a syntactically valid,
cryptographically valid, semantically invalid message sails through
cheap checks into expensive stages. The intake pipeline therefore
orders cheap rejection ahead of expensive verification, and memoizes
the one unbounded walk. Per-stage worst case for one hostile message:

| Stage | At most | Enforcement |
|---|---|---|
| Mailbox handover | 96 KiB NIP-44 ciphertext, 64 KiB opened bytes | `MAX_MAILBOX_CIPHERTEXT_LEN` rejects before NIP-44 decryption and before the envelope is held; `MAX_MAILBOX_OPEN_BYTES` rejects opened bytes before ingest; unopenable envelopes discard with no fact |
| Control framing | 82-byte floor, then version / drive / epoch-key lookups | `SealedControl::decode` + `ControlInbox::ingest` reject before any crypto |
| Suppression redelivery | one hash over the sealed bytes, never an AEAD open | remembered verdicts apply before `open`; the id covers the sealed bytes so the verdict is stable across the open boundary |
| Announcement | two hash-map reads before one BIP-340 verify | membership lookup + epoch agreement precede `verify_announcement`; unseen transitions defer, mismatches and reader-authored announcements suppress, verification still gates every commit |
| Transition | length + count gates before observation | `check_total_len` / `check_transition` (`Limits::V0`) precede `MembershipLog::observe`; signatures verify inside chain analysis |
| Chain traversal | one full analysis per observed-set version per batch, regardless of verdict reads | `MembershipLog` memoizes the analysis; `observe` is the only mutation and invalidates. Verdict reads borrow the cached maps (no per-lookup copies). No depth cap by design (10k-deep chains are pinned conformance) — the bound is analyses-per-batch, not depth |
| Capability | one ECDH+AEAD unwrap of envelope-bounded bytes, then one memoized authorize | `WrappedCapability::unwrap` before `AuthorizedCapability::authorize`; unknown transitions defer into the 1024-bound pending shed, terminal history suppresses |
| Rotation delivery | device check + transition decode + limits + epoch agreement before the unwrap | structural gates precede `WrappedCapability::unwrap`; the transition↔capability binding check stays after it (the binding lives inside the wrap) |
| Manifest / object fan-out | none on intake, by construction | intake commits only transition / announcement / capability / control-message facts and never opens manifests, trees, or chunks; expansion is pull-based post-intake under the fetch byte ceiling and manifest count gates |
| Commit rate | no time-based cap | structural: invalid commits 0 facts, replay commits 0 facts, over-limit deferrals shed with the relay retaining. Insider commit-rate bounding is the separate fact-log spam issue, not this table. The *writer's* own commit rate is POSIX-boundary driven and is treated as a retention question in [Cumulative storage growth](#cumulative-storage-growth) |

## Bytes in flight

Fetch execution is single-threaded per pass, so "bytes in flight" is
the admitted-but-unlanded set: at most `max_admit_per_pass`
identities, each at most `Limits::V0.max_object_bytes` (the ingest
ceiling rejects anything larger before it lands). The admission count
is therefore the byte bound's coarse handle:

> bytes per pass <= `max_admit_per_pass` x `Limits::V0.max_object_bytes`

There is no independent byte knob: the ingest ceiling already caps
the per-object term, and capping admissions caps the sum.

## Cumulative storage growth

> **Not a live bound.** Everything above this line in the document is
> a bound the daemon enforces today. This section is analysis and
> screening: it states the retention bound, the adversary, and which
> bounds could be enforced before GC exists. The only rows here that
> describe current behavior are the two in "Already bounded" — those
> two are enforced. The per-device quota is a proposal, not code.

Every bound above is a *live-process* bound: it caps one operation, one
pass, or one set of open handles, and each is released when the
operation ends. None of them caps **retention**. The store is
append-only with no GC in v0 (`AGENTS.md` hard rule; see also
`crash-consistency.md`, unreferenced objects are never reclaimed), so
committed bytes are never reclaimed: a bound that refuses the
thousandth concurrent write is irrelevant to a member who commits
serially forever. This section states the retention bound
separately, because it is the one resource none of the bounds above
can touch, and because a later GC design needs a defined adversary
rather than an open assumption. (The append-only membership log is
unbounded in depth for a related reason — by design, no depth cap —
but it is owner-gated and grows per membership transition, not per
authored byte, so it is not an amplification path.)

### The bound, stated

The counting variable is **per retaining device**, not per authoring
seat: a replica that authors nothing still retains what it is sent.

> retained bytes <= (snapshots retained) x (per-snapshot fixed
> overhead + content-proportional bytes)
>
> where snapshots retained = locally authored + materialized from
> peers

On the author's own device the term is set by its own commit rate. On a
replica it is set by **its peers'** commit rate, which is the whole
reason the author is not the only bearer. The fixed overhead is also
per *recipient* for the announcement leg, so a member with N devices
pays that term N times per snapshot.

The **fixed** term is the architectural problem. It does not shrink
with change size, it is not reduced by content-addressed chunking or
copy-on-write trees, and it dominates for small writes. Optimizing
the per-commit cost (`seal_tree`, chunking) cannot bound it; only
reducing the *number* of commits can, which is the mutation-unit
question in `write-path.md`, not a micro-optimization.

### Per-snapshot fixed overhead

One commit pays each of these regardless of how many bytes changed
(`write-path.md` commit steps 1-6):

| Fixed cost | Where | Notes |
|---|---|---|
| Rebuilt tree nodes for the mutation | step 1 | content-proportional in cardinality even when the file content is not: a namespace-only change still writes a fresh root node |
| Signed snapshot body | step 2 | author identity key, bound to DriveId and authorizing transition |
| Vault import, including a freshly sealed root manifest | step 2 | temp + fsync + rename + directory fsync; `author_over` seals the hierarchy on every commit, so the root manifest is new bytes per commit even when nothing below it changed |
| Fact-log append + `CURRENT` rewrite | step 3 | append-only and crash-safe; one commit per snapshot |
| Durability fsyncs | step 3 | object store, vault, fact log, and every directory created on the way, made durable **together** |
| Announcement obligation recorded, then discharged | steps 3, 6 | durable outbox, per-recipient delivered markers, byte-identical sealed retries per route — so this term scales with recipient count, it is not a per-commit constant |
| Serving mirror write-through + flush barrier | step 5 | bounded per-pass (64 items / 64 MiB), but paid per commit |
| Projection generation bump + head swap | step 4 | one short write lock |

The fsync count is the term that actually costs wall-clock: step 3
makes several stores durable *together*, and a first-write hierarchy
syncs its directories level by level.

### Content-proportional bytes

Small because a mutation materializes only what it touches: a commit
rebuilds the affected tree nodes and the file's chunk list, and reuses
unchanged nodes, chunk objects, and recorded representations
(including manifest mappings, where the epoch rules allow). A one-byte
edit to a large file does not copy the file.

Each *object* is separately capped by `Limits::V0`
(`wyrd-sync/src/ingest.rs`): 64 MiB per object pre-decode, 256 KiB
chunk payloads (plus the 6-byte envelope header), 65,536 chunks per
file, 1M tree entries, 580K manifest entries, 1M manifest children.
These are per-object ceilings, so they bound the content term of any
single snapshot and nothing about how many snapshots exist.

### What drives the snapshot count

No debounce or autosave timer exists in the code. Snapshots are
created by POSIX boundaries on the device, which for a replica means
its peers' commits, not its own syscalls:

- `write` only buffers; a snapshot is created by `flush`, `fsync`, or
  `release` on a dirty handle. A committing boundary on a **clean**
  handle performs no snapshot, so idle flushes are free.
- `O_SYNC` / `O_DSYNC` deliberately forfeit coalescing: each
  successful `write` is its own durable snapshot. This is the
  amplification peak, and it is opt-in per handle by the application.
- Each namespace operation (`create`, `unlink`, `mkdir`, `rmdir`,
  `rename`, `truncate`, `set-exec`) is one snapshot.

So the rate is chosen by the member, at their own throughput, and is
not throttled by any protocol timer.

The cheapest attack is therefore not `write 1 byte, commit, repeat`
— it is **pure namespace churn**, `unlink` + `create` on one path, in
a loop. That is two snapshots per iteration while writing **zero
file-content bytes**, so the file-content term drops out. What does
not drop out is the per-snapshot cost that is not file content: each
iteration still writes a rebuilt root tree node and a freshly sealed
root manifest, and still pays a signature, a fact-log commit, the
durability fsyncs, and a full announcement set. The bound's remaining
term is therefore the fixed term in full, multiplied without limit.

### Already bounded (writer-side amplification)

Both writer-side paths named in the storage-bound discussion are
closed, and are recorded here so they are not re-opened as findings.
These two rows describe enforced behavior, not screening:

| Path | Bound |
|---|---|
| Repeated failed wants appending unchanged `Fact::Materialization` | Closed. `Engine::set_materialization` / `set_materialization_from` compare durable state first and append nothing when it already equals the target, so a retried want costs no fact and no fsync. Both append sites are guarded (`runtime/engine/mod.rs`), pinned by `repeat_materialization_admission_commits_nothing` — a ten-deep retry storm commits nothing, and a genuine transition commits exactly once |
| Unbounded serving-mirror import queue | Closed. `MAX_MIRROR_QUEUE_ITEMS` (64) and `MAX_MIRROR_QUEUE_BYTES` (64 MiB) in `serving.rs`; a full queue returns `VaultError::MirrorFull` and keeps the vault file durable. Pinned by `a_full_mirror_queue_applies_backpressure_without_losing_the_vault` and `an_oversize_reservation_fails_before_queueing` |

The remaining growth is the commit path itself, which is bounded per
commit and unbounded in count.

### Who bears the cost

| Party | Bears | Bounded today |
|---|---|---|
| Author | local disk, and its own fsync and announcement cost | yes, per operation |
| Serving member / peer | the fact log and snapshot bodies for every snapshot it accepts, whether or not it wanted the content; manifests and chunks only when a want pulls them, under the fetch ceilings | partly — the fact-log and snapshot-body half is not gated at all |
| Vault | retained ciphertext per representation, and the count of them | no |

The asymmetry is the finding, and it sits in that split. Intake
commits only transition / announcement / capability / control-message
facts and never opens manifests, trees, or chunks, so a peer retains
the *history* of what a member did unconditionally, while the
*content* is pull-based. Amplification therefore costs a peer
something it did not ask for even when it never fetches a byte.

Authorization in v0 is membership, and membership carries **no
retention obligation and no refusal right**: `trust.md` records that
object admission is content verification with no per-object ACLs, and
availability is explicitly called out as "not a confidentiality
break" — but nothing lets a peer or vault decline to retain what an
authorized member authored. One member can force unbounded growth on
every other member and on every vault, at a cost to the attacker that
is one signing key and a tight loop. Adding a peer refusal right would
change the authorization contract, so it is recorded as an open
question below rather than decided here.

### Pre-GC bounds: what could be enforced

**Nothing in this subsection is implemented.** It records which
bounds survive the durability contract, so the GC design starts from
a screened list rather than re-testing rejected options.

Enforcement must not contradict the durability contract. Three of the
obvious candidates fail that test, and the fourth is deferred:

- **Snapshot rate limiting is not available pre-GC.** `flush` and
  `fsync` are semantically equivalent and the commit boundary *is*
  the durability boundary (`write-path.md`); a rate limit would have
  to either delay or fail a call that POSIX says is already durable,
  and `O_SYNC` promises one durable snapshot per write. Delaying a
  reported-durable commit is a correctness regression, not a bound.
- **History-depth policy cannot be enforced without GC**, because
  there is nothing to prune when the policy is exceeded; it can only
  be observed and reported.
- **Vault pinning limits are not screened separately**, because any
  form of them — a cap on what a vault will hold for one drive — *is*
  the retention refusal right below, wearing a different name. It
  inherits that decision rather than pre-empting it.

One candidate survives, and it is the only pre-GC bound that reuses
an existing error path unchanged:

| Bound | Enforcement | Why it is safe |
|---|---|---|
| Per-device retained-bytes quota (proposed) | Refuse the commit before step 1's first durable write, as `ENOSPC` | `ENOSPC` from `flush`/`fsync` is already a legitimate reportable outcome, and quota-full already classifies as `StoreFailure::StorageFull` → `ENOSPC` for mount writes (see Disk classification). A quota is a smaller disk, not a weaker promise |

The refusal point is load-bearing and easy to get wrong. Steps 1-2
already write durably (rebuilt objects into the store, sealed
envelopes into the vault, each temp + fsync + rename + directory
fsync), so a quota checked at step 3 would refuse *after* spending
the bytes it was trying to protect: the effective ceiling becomes
quota + one commit, and every refused attempt permanently spends
budget, because with no GC those objects are unreclaimable. The check
has to precede the first durable write of the commit, or account for
the in-flight commit's bytes explicitly.

A quota would bound the author's own device and convert a silent
unbounded growth into an explicit, documented, POSIX-legitimate
refusal. It would not bound the author **on other devices, nor in the
vault**. Nothing in v0 can bound the author, because a member's
commits are valid work and GC is the only mechanism that can make old
bytes stop existing.

### Open questions

1. **Do serving members and vaults get a retention refusal right?**
   This is the only pre-GC bound that limits the *author*, and it is
   a `trust.md` authorization change, not a resource-limit change:
   membership currently implies unbounded retention. Options are a
   per-drive byte ceiling with `ENOSPC` at the serving boundary, an
   eviction-under-pressure rule (which trades against the recovery
   property that motivates the append-only store), or accepting
   unbounded peer growth until GC. Not decided here.
2. **Quota granularity and refusal point**: per device, per drive, or
   per member-set, and how the check sequences against the commit's
   durable writes. Two constraints are already known and both must
   hold. The refusal must precede step 1's first durable write, or
   account for the in-flight commit's bytes, or the ceiling degrades
   to quota + one commit and each refusal permanently spends budget
   (no GC reclaims it). And a quota-refused commit must not leave a
   durable announcement obligation behind: the obligation is created
   at step 3, atomically with the commit, so the refusal has to
   happen at or before that boundary too.

Tracked by the two follow-ups raised with this section:
`protocol(storage): decide whether peers and vaults get a retention
refusal right` (open question 1) and `feat(storage): per-device
retained-bytes quota at the commit durability boundary` (open question
2).

## Disk classification

A full or unwritable disk is classified once, at the I/O boundary,
by [`StoreFailure::of_io`](../crates/wyrd-format/src/store.rs) — one
rule shared by the plaintext object store and the sync vault, so the
two disk writers can never disagree on what "full" means:

| Condition | `StoreFailure` | Sync fetch | Mount reads | Mount writes |
|---|---|---|---|---|
| disk/quota full | `StorageFull` | pass aborts (`EngineError::Store`) | `ENOSPC` | `ENOSPC` |
| store not writable | `PermissionDenied` | pass aborts (`EngineError::Store`) | `EACCES` | `EACCES` |
| anything else | `Transient` | counted as `local_failures`, retried | `EIO` | `EIO` |

Raise vs count follows `error-conventions.md`: a fatal disk
condition aborts the pass (retrying without freeing space or fixing
permissions converges to nothing, and succeeding while nothing lands
would stall silently), while transient refusals count per item and
retry next pass. The run loop classifies each failed pass as mailbox,
store, or engine and supervises the classes independently, with
equal-jittered capped backoff and a separate consecutive-failure cap
per class: a store failure terminates the mount after a few passes (a
dead disk does not heal on retry), a mailbox failure rides out a long
relay outage on an otherwise healthy mount, and any other engine
failure uses the configured generic cap. A supervisor restarts the
process and durable state picks up cleanly.

Data faults stay separate: identity mismatch and corruption are error
variants on each store's own type, never `StoreFailure` — they are
sender or content problems, not resource conditions.

## Pressure signals

No separate metrics pipeline in v0; pressure reads through existing
surfaces:

- `SyncReport` / `ExecuteReport`: per-pass admitted wants, committed
  objects, `unfulfilled`, `local_failures`, `transport_errors`.
- `MailboxHealth::saturation_recoveries`: saturation replays issued
  (a rising count means the relay stream is chronically choked).
- POSIX errnos at the mount (`ENOSPC`, `EACCES`, `EMFILE`,
  `EAGAIN`): the refusal itself is the signal, logged per request
  by the backend's request probe. One exception is mount-wide, not
  per-request: `EIO` at the open boundary can mean a poisoned
  handle mutex, which fails every open until that handle is
  released.
- `LiveError::Engine(EngineError::Store(_))`: the pass-failure
  form of a fatal disk condition, in the store class with its tight
  backoff and cap, so it terminates the mount quickly rather than
  spinning against a dead disk.

## Mailbox saturation

Recorded here because the acceptance criterion names it: saturation
cannot silently lose control-plane work. At saturation `recv` stops
pulling from the notification channel (backpressure, not loss) and
held mail rotates so the engine drains room free; nothing is ever
consumed-and-dropped, because the live stream has no cursor and a
dropped event would wait for a resubscribe that may never come. The
bounded seen-id log (65,536 acks) and poison cache (4096 entries)
bound the durable and in-memory dedupe state. The SDK applies a 512 KiB
normalized-JSON wire backstop, and the relay-event ceiling is checked
before an event enters the notification channel. The latter bounds the
decoded event payload estimate (content plus tag values), not the raw
wire frame: the SDK has already parsed the event at this point, so JSON
escaping is outside the metric. An oversized event is discarded without
acknowledgement, so the relay retains it for redelivery. Proven by the
`mailbox::tests_delivery` and `mailbox::tests_mailbox` suites.
