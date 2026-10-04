# The Mounted Write Path

Normative design for writing through the mount: how POSIX mutations map
onto immutable snapshots, which handle state is captured and validated,
when a change is durable versus visible versus announced, and what the
mount refuses. It is the write-side companion to `fetch-on-open.md` (the
read side).

Tracking issues (titles; fetch nevents with `ngit issue list`):

- `docs(write-path): design the mounted write path`
- `feat(format): mkdir, rmdir, and rename mutations`
- `feat(fuse): mounted write operations`

Landing order: this doc → format mutations → FUSE write operations. The
composition seam (`refactor(daemon): make runtime ownership and
projection publication explicit`), projection-generation caches, and the
announcement outbox land as their tracked issues require.

## Three levels, kept distinct

The design fails if these are conflated:

1. the **POSIX mutation unit** — a byte range (`write`, `truncate`) or a
   namespace operation (`mkdir`, `rename`, ...);
2. the **Wyrd mutation-construction unit** — the affected immutable tree
   nodes and file chunk list that must be rebuilt;
3. the **commit / durability / visibility unit** — the snapshot.

POSIX is byte-range, in-place, incremental, and per-descriptor; Wyrd is
immutable and content-addressed. There is no in-place write to map a
`pwrite` onto, so:

> **The unit of commit is the snapshot, not the byte range.** A commit is
> a new snapshot over a new root; heads are the drive's state.

But snapshot-level atomicity is **not** whole-drive materialization and
**not** whole-file rewrite. A mutation materializes only what it touches:
the path's tree nodes and the affected file's plaintext. Unchanged tree
nodes, chunk objects, and recorded representations are reused, and the
snapshot still covers the whole logical tree because it references the
unchanged subtrees by identity. Whole-file re-chunking is a **v0
implementation constraint**, not an architectural consequence of
immutability; the architecture admits range-scoped reuse later without a
protocol change.

```text
POSIX op                     mount                         drive
────────                     ─────                         ─────
write(fd, off, data)   ┌──► WritableHandle
                       │    ├── base snapshot + file identity
                       │    ├── buffered overlay
                       │    └── dirty
                       │         │ forcing event (DG-1 table below)
create/mkdir/rename ───┘         ▼
truncate/unlink ...      bounded MutationQueue (FIFO, total order)
                                 │
                                 ▼
                             daemon loop (the only engine user)
                              1 validate current base (stale?)
                              2 apply the mutation in the store
                              3 author + durably commit the snapshot
                                (records the announcement obligation)
                              4 publish the projection
                              5 flush serving residency
                              6 discharge the announcement obligation
```

## Mutation/commit boundary table (DG-1, normative)

Decision OD-1 (record at the bottom of this document): coalescing
policy **A, independent of the POSIX mutation unit, with dirty-handle
release as a forcing event**. Given an arbitrary sequence of POSIX
mutations, the system commits exactly one snapshot per commit-forcing
event — not one per mutation — and the pending state between commits
is never durable, never servable, and never announceable.

```text
POSIX operation sequence
        ↓
pending mutation set          (Working: volatile, memory-only;
                               never durable, never servable, never announceable)
        ↓
commit-forcing event?         (the table below)
        ↓
snapshot boundary              (one snapshot per forcing event, folding all pending)
        ↓
durability level               (Working | Committed | Published — local axis only;
                               the level encoding is owned by DG-2 and referenced here)
        ↓
servable?                      (only ever yes past the snapshot boundary + serving residency)
        ↓
announceable?                  (only ever yes past serving residency)
```

| Event | Pending empty | Pending non-empty | Snapshots | Yield |
|---|---|---|---|---|
| Buffered `write` / handle `truncate` / handle `set-exec` (non-`O_SYNC`) | Accumulate | Accumulate; never forces | 0 | Working |
| `fsync` / `fdatasync` on a handle whose path has pending data anywhere | n/a (this handle's buffer may itself be a pending member) | Fold all pending into one snapshot | 0–1 | Committed → Published via the pipeline; 0 only when no member survives (rule 6) |
| `fsync` / `fdatasync` on a handle whose path has no pending data anywhere | No-op; commits nothing | No-op | 0 | Unchanged |
| `flush` on a **dirty** handle (this handle holds its own buffer) | n/a | Fold all pending into one snapshot | 0–1 | Committed → Published via the pipeline; 0 only when no member survives (rule 6) |
| `flush` on a clean or read handle (including the kernel-injected close-time flush) | No-op; never forces on another handle's behalf | No-op | 0 | Unchanged |
| `release` / `close` of a **dirty** handle (this handle holds its own buffer) | n/a | Fold all pending into one snapshot, best-effort | 0–1 | Committed → Published; errors often discarded by callers; 0 only when no member survives (rule 6) |
| `release` / `close` of a clean or read handle | No-op; never forces on another handle's behalf | No-op | 0 | Unchanged |
| `O_SYNC` / `O_DSYNC` `write` | Its own durable snapshot, shared with any pending set | Fold pending + this write into one snapshot, synchronously before return | 0–1 | Committed → Published; 0 only when no member survives (rule 6) |
| Effective namespace op (`mkdir`, `unlink`, `rmdir`, `rename`, path-addressed `truncate` / `set-exec`) | Its own snapshot | Fold pending + self into one snapshot, synchronously before return | 0–1 | Committed → Published; 0 only when no member survives (rule 6) |
| No-op submission (`rename` to the same path, `truncate` to the current size, `set-exec` to the recorded mode, the `O_TRUNC` follow-up fh-less `setattr(size=0)`) | Submits nothing | Submits nothing; forces nothing | 0 | Unchanged |
| `create` / `O_TRUNC`-open | Commits an empty file / truncation, folding any pending set | Fold pending + self into one snapshot; the returned handle binds the just-committed identity | 0–1 | Committed → Published; 0 only when no member survives (rule 6). A `create` refused at admission (`EEXIST`, `ESTALE`, `ENOENT`) submits nothing and forces nothing — the refusal is decided before any fold |
| Daemon shutdown / `destroy` (SIGINT/SIGTERM, unmount) | No pending set exists | Fold all pending into one snapshot, best-effort per path | 0–1 | Existing teardown semantics, coalesced |
| Explicit checkpoint (reserved) | No-op | Fold all pending into one snapshot | 0–1 | API/CLI surface defined in the implementation; the name is reserved here |
| Elapsed time alone | Never forces | Never forces | 0 | No bounded idle window in v0.3 (rejected below) |

Rules:

1. **Fold, don't sequence.** A forcing event commits the whole pending
   set plus itself as a single snapshot, not pending-as-one plus
   self-as-another. `fsync` on one handle therefore makes other
   handles' pending data durable too — extra durability, never less,
   except through rule 2's tie-break: a losing member's buffer is
   discarded rather than committed, and the loser can be destroyed by
   an unrelated third party's fold (an `O_SYNC` write, `release`, or
   shutdown on another path) when the forcer has no member on the
   tied path. Apart from the tie-break, the folded data is durable
   at the boundary, so serving and announcing it with the snapshot is
   safe.
2. **Stale and conflict checks are per member, at commit.** Members
   are ordered first-in-first-buffered (FIFO by buffering time), which
   is deterministic. Same-path concurrent edits fail closed for the
   conflicting member (its handle goes terminal `EIO`); different-path
   edits rebase onto the current head and still fold into the one
   snapshot. On a same-path tie the forcing member wins whenever the
   forcing event carries privilege — `fsync`/`fdatasync`, `flush` on
   a dirty handle, `O_SYNC` write, effective namespace op,
   dirty-handle `release`, `create`/`O_TRUNC`-open, and the explicit
   checkpoint all carry it — so an explicit durability call never
   loses its own bytes to an earlier-buffered member; the earlier
   member goes terminal instead. A truncating `open` therefore keeps
   today's commit outcome with earlier loss: the truncate wins its
   path tie and any dirty handle on that path goes terminal `EIO`
   at the fold — where today it would keep buffering and only go
   stale at its own later commit — rather than the open failing
   because another handle held unflushed bytes. If the fold
   itself cannot be authored (conflicted drive, store failure), the
   open fails with the existing binding-rule errno (`EIO`/`ESTALE`)
   and nothing commits — there is no half-truncated state for the
   returned handle to bind. Shutdown/`destroy` carries no privilege
   (no caller to honor; best-effort, errors logged), so a shutdown
   fold breaks ties earliest-buffered. When the forcer has no member
   on the tied path, the earliest-buffered member wins. Either way
   the inverted case is explicit: the losing member's handle is
   terminal `EIO` at the fold, before it ever makes its own forcing
   call. More than one eligible live head refuses the whole fold
   (`ConflictedHeads`); nothing commits.
3. **`flush` ≡ `fsync` stays the reportable persistence point for the
   calling handle's own data** and `O_SYNC` stays commit-per-write;
   coalescing applies only to demand that does not explicitly require
   synchronous durability. For `fsync`/`fdatasync`, "clean" is a
   per-path property: a boundary on a handle whose path has no
   pending data anywhere commits nothing and forces nothing, which
   keeps idle syncs on untouched paths free while preserving the
   per-inode `fsync` contract — an `fsync` on any descriptor of a
   path with pending data makes that path's data durable. For
   `flush` and `release`/`close`, "clean" is a per-handle property:
   only a handle holding its own buffer forces, and a clean or read
   close — including the kernel-injected close-time `flush`, which
   `fuser` does not require to flush pending writes — never forces
   on another handle's behalf. The `flush` ≡ `fsync` equivalence
   covers the caller's own bytes and must not pull the close path in
   with it.
4. **No idle-window commit in v0.3.** A timer in the durability path
   would be a silent post-timeout commit, contradicting the queue's
   synchronous contract below (a caller stays blocked until the loop
   completes its request; nothing commits after the caller returns),
   and POSIX requires `fsync` itself to be the synchronous durability
   point rather than a timer the caller never invoked. Revisit only
   with explicit durability semantics.
5. **Pending is Working, never more.** The pending set is volatile
   memory: it populates no cache keyed on durable revision, appears
   in no manifest, satisfies no projection or transport serving
   request, and creates no announcement obligation. (The writing
   handle's own overlay still gives read-your-writes.) A crash loses
   exactly the pending set; that loss is the contract, not a
   violation. The `Working | Committed | Published` labels are
   descriptive here; DG-2 owns the level encoding and API contract.
6. **Fold failures are per member, except the fold-fatal classes.**
   Surviving members still commit into the one snapshot; each failed
   member reports its own errno to its own waiter and its handle goes
   terminal. The forcing caller receives the errno of its own member
   — an `O_SYNC` write is never failed by an unrelated member's
   staleness, and a namespace op reports only its own outcome. At
   shutdown/`destroy` the same rule holds best-effort per path:
   committed members stay committed, and per-path losses are logged
   rather than reported. A fold with no surviving member authors
   nothing: no empty snapshot, no dangling announcement obligation.
   Fold-fatal (whole-fold, unattributable to one member):
   `ConflictedHeads` (refuses the entire fold, nothing commits);
   store, authoring, or fact-commit failure; and the pre-commit
   retained-bytes quota, which under folding covers the aggregate of
   the whole pending set before the commit's first write.
   Post-durable stage failures (publication, serving residency) are
   likewise not member-attributable: the commit already succeeded, so
   monotonicity fixes the outcome and the caller learns nothing.
7. **Folded handles advance atomically with the snapshot.** Every
   member whose data committed has its base advanced to the committed
   identity and its dirty bit and budget cleared as part of the same
   commit — otherwise its next commit would go stale against bytes it
   already committed. The fold is orchestrated in `wyrd-core`, but the
   per-handle post-commit transition executes in the handle owner
   (today the daemon FUSE backend's `WriteHandle`); the implementation
   must not split base-advance from the commit it belonged to.
8. **What improves.** Folding removes one snapshot per folded forcing
   event, so the win is proportional to forcing events avoided per
   logical save: `fsync`+`rename` save sequences go from two snapshots
   to one, and several simultaneously dirty handles commit once
   instead of once each. A single `fsync` per save with one dirty
   handle — the plain debounce-save loop — commits one snapshot
   before and after, so the headline workload is unchanged until the
   implementation batches across saves; likewise open/write/close
   churn still commits per cycle because `release` forces. The
   observability baseline must measure these shapes separately.

## Writable handles

One writable open handle owns one buffer; it is the only mutable write
state in the system. A handle captures:

- its **path** (also the namespace location the stale check resolves) and
  the **base snapshot** it opened against;
- the **base file identity** — the opened tree entry's identity: kind
  (`RegularFile`), size, exec bit, and ordered chunk ids. This is the
  value the stale check compares; an implementation may compare a
  domain-separated digest of the tuple rather than retain the chunk list
  literally, but the comparison must cover kind, size, exec, and content.
  A change of kind — file→directory, file→symlink, or removal — is
  stale, not just a content change;
- the **buffered overlay** (a logical file image, see below);
- its **open flags** (`O_APPEND` changes commit semantics);
- a **dirty** bit.

The overlay is an **implementation abstraction**: the semantic contract is
that a read of the handle returns `overlay(base, buffered_mutations)` over
the requested range. Whether the implementation stores a dense buffer,
patches, a rope, a spill file, or chunk-scoped overlays is free. The
overlay is bounded (see resource bounds); it is not required to hold a
whole large file in memory.

Overlay semantics, stated exactly:

1. The overlay is a logical byte image over the base. `write(offset,
   data)` sets those bytes; a write beyond the current logical end
   zero-fills the gap (sparse files are not representable, so a hole
   materializes as zeros). Overlapping buffered writes are
   last-write-wins *within the handle*.
2. Reads on the same handle observe the overlay (read-your-writes).
   Reads on other handles and new opens observe the last committed head;
   the read side's open-time capture is unchanged.
3. The overlay's logical size is the max of the base size and every write
   end; `truncate` resets it. `write` past the end then re-extends with
   zeros.
4. **`O_APPEND` is an ordered byte-string sequence, not positioned
   writes.** Each write appends its bytes to the handle's append sequence
   in submission order; the sequence is not resolved against any offset
   until commit. At commit the sequence is appended to the **current**
   file contents (below). This is why an append handle's base identity is
   used only for existence/kind, not for content equality.

A handle returned by `create` is **ordinary writable-handle state** once
returned: it captures the created empty file's identity and path like any
other handle. There is no privileged relationship between a handle and
the snapshot that created it, and it can go stale exactly like any other.

## Commit admission: the mutation queue

FUSE never authors. A committing operation submits a `MutationRequest`
and blocks; the live loop is the only engine user. This mirrors the want
registry but is deliberately **not** a demand that outlives its waiter.

```text
MutationRequest {
    id: MutationId,        // unique per submission; diagnostics, tests
    kind: MutationKind,    // file commit, create, mkdir, unlink, ...
    path(s): …
    base: Option<FileIdentity>,  // handle commits only
    parent: Option<ParentToken>, // create only; session-local
}
```

1. **Total order.** The queue establishes the total order of local
   mounted mutations; mutations execute serially in admission order.
   Submission order and execution order coincide, so snapshot parent
   selection is deterministic: each mutation's snapshot parents are the
   heads after the previous mutation. A mutation held for authoring
   prerequisites rejoins in submission order, so the total order
   survives the hold.
2. **Bounded.** `MAX_PENDING_MUTATIONS` bounds all admitted, incomplete
   requests — including the request currently executing and any held
   for prerequisites, not just those waiting. Admission beyond it
   returns `EAGAIN`. The queue has its own lock, never the view's or
   the store's. Shutdown closes admission:
   once the live loop stops, new submissions are refused with `EIO`
   (`Shutdown`) instead of queueing behind a loop that will never drain,
   and held requests resolve `Shutdown` like any other queued request.
3. **Synchronous, no silent post-timeout commit.** Unlike a fetch want
   (which may outlive its waiter), a mutation's caller stays blocked
   until the loop completes it — including across held passes. Once
   admitted the request either commits or fails before the caller
   returns. There is no path where `fsync` fails and the mutation
   nevertheless applies later.
4. **Held for authoring prerequisites, with a deadline.** A mutation
   whose base closure references remote-only content cannot author:
   the resolver (`ChunkUnavailable`) names the missing chunk, the loop
   registers it as an ordinary fetch want, and the mutation waits —
   pinned to the single head its first evaluation used, so the retry
   can never silently rebase onto newer state. A changed, emptied, or
   multiplied head set fails the retry `Stale`, exactly like a raced
   handle commit. The wait is bounded by `max_mutation_wait` (default
   30s, wall-clock from admission — the caller has been blocked since
   then — checked on the first evaluation and every pass after); past
   it the mutation fails `ETIMEDOUT` — retryable information, not a
   system failure. A first evaluation that arrives after the budget
   already ran out fails the same way instead of starting a fresh
   wait. A mutation evaluated headless or multi-head never
   holds: nothing meaningful pins, so it fails closed as before.
   The wait is a wall-clock bound on the loop, not just on the
   check: while any mutation is held, the pass's fetch runs under the
   nearest deadline's remaining time — each attempt is capped at what
   remains and the plan stops starting fetch work once the budget is
   spent, so one stalled provider cannot push the `TimedOut` decision
   past its bound (unstarted work stays pending for the next pass).
   With nothing held, fetching is unbounded. A pass that fulfills
    fetch objects with mutations still queued
   wakes the loop immediately, so a held mutation retries without
   waiting out the idle pacing deadline.
5. **Create parent precondition.** FUSE captures an opaque, session-local
   `ParentToken` when `create` observes its parent directory. The live loop
   checks that token immediately before authoring. Tokens are stable across
   changes to descendants and siblings, so ordinary serialized mutations
   do not invalidate a create. A successful local namespace operation that
   removes, replaces, or moves a path invalidates that path and its
    descendants; captures are held closed until the new projection publishes.
    If publication is deferred because a new head's closure is still
    fetching, captures reopen against the still-served projection; the
    execution-time head and strict-parent checks remain authoritative.
    A head-set change outside the local queue invalidates all tokens
   conservatively because the current object model carries no path-incarnation
   metadata. A missing parent is `ENOENT`, a non-directory parent is
   `ENOTDIR`, and an invalidated parent is `ESTALE`. Conflict classification
   is checked before these path-specific results. Tokens are not durable,
   portable, or authorization values.
6. **Liveness consequence (named).** The daemon synchronization loop is a
   hard liveness dependency for every committing FUSE operation: a wedged
   loop blocks the caller indefinitely. That is a daemon health failure
   bounded by the process supervisor, not a per-request cancellation, and
   it is the deliberate price of the no-post-timeout guarantee. Loop
   *exit* is different from a wedged loop: terminal error or shutdown
   resolves every admitted-but-incomplete request with `EIO`
   (`Shutdown`) instead of stranding it, and the closed queue refuses
   new submissions the same way.
7. **Publication is the same path as fetch.** A mutation applies under
   the store write path and publishes heads and materialization under
   one short view write lock, exactly as a fetch pass does. Neither lock
   is ever held across a network wait.

The rejected alternative is sharing the engine behind a mutex with the
FUSE thread: it dissolves the single-authority discipline, contends with
intake and fetch, and complicates the loop's dirty/republication
invariant.

## The stale-handle boundary (no lost updates)

This is the core correctness rule. Two writable handles on the same file
must not silently overwrite each other.

> A handle commit is accepted only if the target path in the **current**
> live head still carries the handle's **base file identity** (or, for a
> create, the name is still absent). Otherwise the commit fails closed
> with `EIO` (`WriteError::StaleHandle` internally) and performs no merge.

Concretely:

```text
HEAD = H0, foo = "AAAA"
A = open(foo)   B = open(foo)        both base foo @ H0
A writes "BBBB"; A commits  →  H1: foo = "BBBB"
B writes "CCCC"; B commits  →  STALE: foo@H1 ≠ base
                                  EIO; no snapshot; "BBBB" survives
```

Two distinct conflicts, both surfaced as `EIO` with separate diagnostics:

- **Drive-level** (`ConflictedHeads`): more than one eligible live head,
  so there is no single tree to mutate.
- **Handle-level** (`StaleHandle`): one live head, but this path changed
  since the handle opened.

The rebase rule is deliberately narrow: a handle commit applies its file
change onto the **current** head, so a concurrent commit to a *different*
path does not invalidate it. Only a change to the same path's file
identity — including a kind change or removal — is stale. `truncate` and
any future handle-derived content mutation obey the same rule.

A stale or failed commit is **terminal for the handle**: the buffered
overlay is discarded and the committing boundary returns `EIO`; the
application must close and reopen (a transient store failure is not
retried with the old buffer, and the daemon keeps no per-handle error
state).

### Rename and unlink versus open handles (v0 decision)

Wyrd v0 chooses the **path-based** rule: a writable handle does not
survive a namespace change to its target.

- If `/a` is renamed to `/b` or unlinked by another commit, the handle's
  captured path `/a` no longer carries its base identity in the current
  head, so its next commit fails `EIO` (`StaleHandle`). `write` still
  buffers; the divergence surfaces at the committing boundary.
- **Read handles keep the captured identity until `release`** even if the
  target is renamed or unlinked: reads do not write back, so the
  open-time capture survives. Only the committing path is strict.

This is a deliberate POSIX divergence: POSIX lets a writable descriptor
survive `rename`/`unlink` and write to the unlinked inode. Wyrd has no
inode and no GC — a write to a node unreachable from the live tree could
not appear in any snapshot — so v0 rejects rather than accepting a write
that could never commit. True node-identity survival (following a renamed
node, or an unlinked open file) is future work that would need a stable
entry identity; it is out of scope here.

**`O_APPEND` is the explicit content exception.** Append is
position-independent, so an append handle does not compare content
identity; it still requires that the target path **exists as a regular
file** in the current head (otherwise `EIO`/`StaleHandle` — append never
creates and never resurrects). Its append sequence is concatenated to the
**current** file contents at commit time, so:

- two append handles serialize in queue order as `old ‖ A ‖ B`;
- an intervening ordinary commit is observed, not rejected:
  `H0 foo=AAAA`, `B` commits `BBBB`, then an append `X` commits → `BBBBX`;
- an intervening change to the path's kind or its removal is still stale.

Append is the only content mutation with this privilege, and it exists
because POSIX defines append against the current end. In v0 the mounted
write path refuses `O_APPEND | O_TRUNC` together (`EOPNOTSUPP`): the
append model has no committed empty base to truncate to, and neither flag
is silently ignored. Enforcement covers both the open-time flags and the
kernel's split delivery (open arrives append-only, the truncation follows
as a separate `setattr`): a path-addressed truncate while an append handle
is open on that path is likewise `EOPNOTSUPP`. An exec change through an append handle is a
path-addressed mutation.

Namespace mutations (`mkdir`, `unlink`, `rmdir`, `rename`, and
path-addressed `set-exec`) carry no handle base: they read-modify-write
the current head under the queue's total order, so each is evaluated
against the state its queue predecessor committed, never against the
state visible when the FUSE syscall began.

A directory rename rebinds the moved directory's own inode on both
mounts, and fresh path lookups under the new prefix work immediately.
Pre-opened handles to *descendants* keep addressing the old path: the
v0 inode table rebinds the exact source mapping only, so a descendant
handle opened before the rename goes `ENOENT` on its next path
operation instead of silently following the subtree. Following renamed
subtrees through open handles is a presentation-layer feature v0 does
not claim.

## The commit pipeline and durability ordering

A commit proceeds in this order, and the order is the contract:

1. **Objects.** Rebuild the affected tree nodes and the file's chunk list
   and insert them into the content-addressed store. Immutable and
   idempotent.
2. **Authoring.** `Engine::author_snapshot` seals the manifest hierarchy
   from representations the device holds (reusing recorded mappings where
   the epoch rules allow), imports the sealed envelopes and the signed
   snapshot body into the durable vault, and commits the snapshot-body
   and manifest facts.
3. **Commit durability boundary.** The object store, the vault, and the
   fact log become durable **together at this boundary** (steps 1-2 only
   *prepared* state; neither is independently durable). The fact-log
   commit is already append-only and crash-safe, and the object store and
   vault share one crash protocol: temp + fsync + rename + directory
   fsync (`wyrd_format::durable`), so a published byte range or sealed
   representation survives a power failure. The rename and the directory
   fsync are distinct outcomes: a rename failure publishes nothing, while
   a post-rename directory-fsync failure leaves the representation
   installed but not known durable. That failure is reported, never
   swallowed, and a later publication attempt (an `insert` or `import`)
   reconciles the directory before reporting success, while an `import`
   also re-imports the representation into the serving mirror. An
   existing entry is not treated as durable until its directory has been
   synced in the current process, so this recovery survives a restart
   rather than living only in memory. A directory created along the way
   is synced level by level, so a first-write hierarchy is durable too.
   The **announcement obligation is recorded durably here**, atomically
   with the snapshot (see below), so a crash after commit still knows the
   snapshot must be announced. The obligation *fact* is appended earlier,
   inside step 2's single fact-commit with the body and manifest facts;
   step 3 is where those facts, and the objects they reference, become
   durable together.
4. **Publication.** Heads and materialization are swapped into the shared
   view under one short write lock. The view sees the old head until this
   step.
5. **Serving readiness.** The vault write-through to the serving mirror
   is flushed (`ServingEndpoint::flush`) so the new representations are
   servable by transport root. The write-through queue is bounded
   (64 items / 64 MiB); a full queue fails the import with
   `VaultError::MirrorFull` while the vault file stays durable, and
   the flush barrier reports not-ready, so the discharge at step 6
   waits exactly like a failed barrier.
6. **Announcement discharge.** The recorded obligation is sent
   with retry through the durable outbox (`Engine::announce_snapshot`
   for one snapshot, `Engine::announce_pending` for the resume path:
   per-recipient delivered markers — one per relay-accepted send, so
   a send no relay accepts leaves the obligation pending for a later
   pass — byte-identical sealed retries per
   route — the canonical seal when its route is live, else the
   persisted route-specific reseal).

**Objects prepared at 1; authoring prepared at 2; durable at 3 (with the
announcement obligation recorded); visible at 4; servable at 5;
obligation discharged at 6.**

### Commit state is monotonic (invariant)

> Later-stage failure never rolls back an earlier durable state.

The state machine is monotonic: `prepared → durable → visible →
servable → discharged`. The announcement obligation is not a later
state in that chain — its fact is committed at step 2 and durable at
step 3 (see below), so it is *eligible* for discharge only once serving
readiness passes at step 5. A failure at a later stage leaves the
earlier states standing; nothing after step 3 undoes step 3. This is
what forbids transactional coupling between the local commit and
network propagation.

### Announcement obligation durability

The obligation to announce a locally authored snapshot is **committed at
step 2, atomically with the snapshot, and durable at step 3** — not
created at step 6. Its fact is appended in the same single fact-commit
as the snapshot body and the manifest facts, so there is no window in
which a snapshot exists without its obligation. Step 6 only
*discharges* it. Therefore outbox-enqueue failure cannot lose an
announcement: if step 3 committed, the obligation is durable, and a
restart reconciles un-discharged obligations back through the outbox
(`Fact::AnnouncementQueued` / `AnnouncementSealed` /
`AnnouncementRouteSealed` / `AnnouncementDelivered`; pending derives
as queued-minus-delivered).
The outbox entry is eligible for discharge only once serving readiness
(step 5) has succeeded for that snapshot — eligibility is
barrier-gated per publish pass (the loop flushes the serving mirror
before discharging announcements), not engine-gated: a failed barrier
skips the discharge and the next pass retries, so a sick mirror stalls
propagation, never the mount.

A head whose closure is still fetching is neither a success nor a
failure: the head installs once its records and trees land, the
previous generation keeps serving until then, and the pass does not
spend the fatal engine-error budget. Only a *damaged* closure (an
identity mismatch, a non-canonical document, a contradicted mapping)
fails the pass closed.

Failure at each stage, explicitly:

- **Before 3 (no durable commit):** no snapshot exists; nothing is
  published; the caller gets `EIO`; the previous head is untouched.
- **After 3, before 4 (durable but not projected):** the snapshot is
  durable and will survive a restart, but the view still serves the old
  head. The daemon's dirty bit forces republication on the next pass —
  the existing "a pass may commit durably before publication" invariant,
  inherited here, makes this recoverable rather than rollback territory.
- **At 5 (visible but not servable):** the new head is legitimate: local
  reads work from the object store, the snapshot stays durable, and the
  obligation stays recorded but **ineligible** — no announcement is
  emitted. Peer fetches fail and retry; the daemon retries serving, and
  the obligation is discharged only after serving succeeds. Serving
  failure is never a reason to roll back a durable, published snapshot.
- **At 6:** local commit and visibility stand regardless of announcement
  success; the durable obligation retries. Peer propagation is never part
  of local filesystem durability.

A contract test pins the serving gate: serving failure → projection
remains the new head, the obligation is recorded but not discharged, and
after serving is retried the obligation is discharged.

## flush, fsync, release

| Operation | Contract |
|---|---|
| `write` | Buffers only. Success acknowledges only that bytes entered a volatile buffer. |
| `flush` | Commits the handle. Success means the commit is **device-local durable** (step 3). |
| `fsync` | Commits the handle. Success means the commit is device-local durable. |
| `release` | Commits best-effort; the error is often discarded by applications; always drops the handle and buffer. |

`flush` and `fsync` are **semantically equivalent** for the calling
handle's own data: there is no cached-but-not-durable commit state —
the commit boundary *is* the durability boundary. They differ in
which events force — `fsync`/`fdatasync` fold on a per-path test
while `flush` forces only on the calling handle's own buffer — and
only in how applications observe the result: `flush` runs on every
`close` and its error is frequently ignored, so `fsync` is the
reportable persistence point. An `fsync`/`fdatasync` on a handle whose path has no pending
data anywhere performs no snapshot and forces nothing, while a
`flush` or `release`/`close` forces only when the calling handle
itself is dirty — a clean close-time `flush` never forces on another
handle's behalf (DG-1 table). A forcing boundary folds the whole
pending set, not just the calling handle.

Because `release` is best-effort and drops the buffer, an application
that never calls `flush`/`fsync` can lose acknowledged writes. This is
standard POSIX-without-`O_SYNC`: `write` is not durable. The mount states
it plainly.

Unmount adds one best-effort safety net, not a durability boundary:
`destroy` attempts to commit every still-dirty handle before dropping
the table. The commit needs the mutation queue open and drained, so
teardown keeps it that way on every path: the loop returns without
settling, the session joins first (destroy submits while the loop's
post-return drain executes), and admission closes only after the join
— see the lifecycle contract in `wyrd-daemon/src/lifecycle.rs`. A
commit that fails its own evaluation (stale handle, conflict, store
failure) is still lost and logged per path, and a crash loses
everything unflushed; flush or fsync remains the reportable
persistence point. But a clean SIGINT/SIGTERM with a healthy drive
now preserves unflushed writes instead of dropping them. On a real
mount the kernel releases every open file before destroy runs, so
`release_handle` is the path that normally preserves signal-time
writes; `destroy` is the net for handles whose release-time commit
failed.

`O_SYNC`/`O_DSYNC` never wait for a later boundary: each successful
`write` on such a handle is durable before returning. Under DG-1 the
write folds any pending set plus itself into one snapshot (a
committing boundary per syscall, shared when other handles have
pending data). That is expensive and correct by construction.

### Error timing

Write-time and commit-time failures are distinct surfaces:

- **`write` itself can fail** without buffering anything: a read-only or
  read-only-opened handle (`EBADF`), a range that overflows the file
  offset (`EFBIG`), an invalid argument (`EINVAL`), or a buffered/dirty
  budget (`ENOSPC`). These are returned by `write`.
- **Commit failures are returned by `flush`/`fsync`** (and best-effort by
  `release`): `EIO` for a stale handle, a conflicted drive, or a
  store/authoring/durability failure; `EFBIG` when the resulting file or
  tree exceeds a protocol ingest ceiling; `ENOSPC` when a protocol object
  budget is exceeded. A `write` that succeeded never implies the later
  commit will. (A configured per-device retained-bytes quota reports
  `ENOSPC` here, reusing this reporting path unchanged. The check runs
  before the commit's first write to disk, not at the durability
  boundary, so a refused commit spends nothing — see
  `storage-growth.md`.)

## Namespace operations

Snapshot boundaries are governed by the DG-1 table above: *effective*
namespace operations are forcing events that fold pending plus self
into one snapshot, while a submission that resolves to no change
(`rename` to the same path, `truncate` to the current size, `set-exec`
to the recorded mode) submits nothing and forces nothing.
`sqlite`-style multi-step tooling is unaffected: each committed state
is a complete, valid filesystem.

| Operation | Semantics (v0) |
|---|---|
| `create` | Commits an empty regular file, folding any pending set, **and** returns a handle based on the resulting snapshot, as one daemon operation (no window between them). The empty-file snapshot is a complete, independently valid state: a crash before the first content commit leaves it, and a peer may observe it. `O_EXCL` → `EEXIST`. |
| `write` | Buffer only; committed by `flush`/`fsync`/`release`. |
| `mkdir` | Creates an empty directory. Does **not** create intermediates: `mkdir a/b/c` is `ENOENT` when `a/b` is absent. `EEXIST` when the name exists. (The mount does not inherit `WyrdNode::put_file`'s intermediate-creation convenience.) |
| `unlink` | Removes a file or symlink entry; `EISDIR` on a directory; `ENOENT` when absent. |
| `rmdir` | Removes an empty directory only (`ENOTEMPTY` otherwise); `ENOTDIR` on a file. |
| `rename` | File→file replaces; file→dir `EISDIR`; dir→empty-dir replaces; dir→nonempty-dir `ENOTEMPTY`; dir→file `ENOTDIR`; a directory into its own descendant `EINVAL`; same path is a no-op. A trailing slash on the source requires a directory. |
| `truncate` | The conceptual operation behind `setattr(size)`: construct the new file representation at the target size. Growing preserves the existing bytes and zero-fills; shrinking preserves the prefix and discards the tail. Obeys the stale-handle rule. A truncate of a path that no longer stats fails with the lookup error and submits nothing. |
| `set-exec` | The conceptual operation behind `setattr(mode)`: toggles the exec bit, the only mode state represented. A path-addressed `set-exec` (or a combined size+mode `setattr`) on a path that no longer stats fails with the lookup error and submits nothing, like `truncate`. |

`truncate` is a **representation construction**, not a mandate to read a
file: the implementation materializes only the ranges needed to build the
new chunk list (shrinking a huge file need not read it; growing appends
zeros). The v0 implementation may materialize the file plaintext through
the normal demand path — that is an implementation strategy, not part of
the contract.

`set-exec` addressed by path is a **namespace mutation** against current
state, so two `set-exec` requests serialize through the queue naturally.
An `fchmod`-style exec change issued through a writable handle is
handle-derived and obeys the stale-handle rule (the exec bit is part of
the file identity).

`rename` notes: cross-directory rename within the drive is allowed
(unchanged subtrees are reused; only the two path walks are rebuilt).
There are no hard links, so entry identity is the *pathname*, not a
shared node — `rename(p, p)` is the only same-identity case, and it is a
no-op. Both paths are parsed as canonical components before the
mutation, so `rename("a//b", "c/./d")` cannot smuggle a non-canonical
spelling.

**Final-component symlinks are never followed.** `unlink`, `rmdir`,
`rename`, and metadata operations target the directory entry itself, not
a target it names. Mounted symlink traversal is also unavailable in v0:
`readlink` returns `EOPNOTSUPP` because a host pathname walk can span
live projection generations. Paths are handled as canonical components,
not raw strings.

### Namespace mutation atomicity (contract)

> Every namespace mutation publishes exactly one new root or none; no
> reader can observe an intermediate tree state.

### Format validation is not bypassable (contract)

> All mounted mutations pass through the same canonical format
> validation and ingest limits as remotely received state
> (`check_tree`/`check_manifest`, `Limits::V0`); the mount is never an
> alternate parser or validator.

Both are named cross-crate contracts (a `wyrd-contracts` test), not
merely implementation properties.

## Open flags

| Flag | Semantics |
|---|---|
| `O_RDONLY` / `O_WRONLY` / `O_RDWR` | Access mode; a write handle is required for `write`/`truncate`. |
| `O_CREAT` | Create the file if absent (commits an empty file, folding any pending set, per `create`). |
| `O_EXCL` | With `O_CREAT`, `EEXIST` if the name exists. |
| `O_APPEND` | Appends at the current end at commit time (see handles); the target must remain a regular file. |
| `O_TRUNC` | The truncation commits **during open** and the handle starts clean on the empty base. It must: the kernel delivers `O_TRUNC` as open plus a separate fh-less `setattr`, so a handle carrying the pre-truncate base would go stale before its first commit. The commit is bound to the identity the open observed, and the handle binds exactly the identity the loop committed: a same-path replacement that lands before the commit fails the open (`EIO`), and one that lands between the commit and the open's capture fails it `ESTALE`. The follow-up fh-less `setattr(size=0)` is the one part that stays path-addressed, like any other `setattr`: it is a no-op here because the truncation already committed — provided the stat succeeds, since a vanished path fails the lookup instead of submitting. A concurrent change *after* open still stales the handle (`EIO`); a path truncate that lands while the opening handle is still clean re-pins it instead (the handle holds nothing to lose). |
| `O_SYNC` / `O_DSYNC` | Accepted; every write is durable before returning, in its own durable snapshot shared with any pending set (see flush/fsync). |
| `O_DIRECT`, `O_PATH` | `EOPNOTSUPP` (not representable). |

## Conflicted drives

A path mutation is a read-modify-write of one tree, so the mount requires
exactly one eligible live head. With more than one, writes fail closed
with `EIO` (`ConflictedHeads`). This does not conflict with `epochs.md`'s
"local write" rule (a member may publish a snapshot parenting onto any
subset of heads): that authorizes a device to *resolve* a conflict by
publishing a snapshot whose parents are all heads; resolution is not a
path mutation and has no mount surface in v0. Reads keep serving the
merged view; writes wait for resolution by other means (resolution UX is
future work).

**Zero heads is not a conflict.** A fresh drive has no live head; its
first mutation authors the initial root from an empty tree (the same
bootstrap `WyrdNode::put_file` performs), so `create`/`mkdir`/`write` on an
empty drive succeed. The conflicted rule applies only to *multiple* live
heads.

## Coherence

1. Every commit advances a **projection generation**. The backend's
   positive/negative lookup results, attributes, and new directory
   streams revalidate against it (`feat(fuse): make directory and inode
   caches projection-generation aware`).
2. **Open captures are pinned.** A file descriptor serves the identity it
   opened; an **open directory handle captures its enumeration
   generation**, so an in-progress `readdir` stream continues its
   captured listing, while a newly opened directory handle observes
   committed namespace changes. This is the directory analogue of the
   immutable file-descriptor rule.
3. An entry whose kind changed (file ↔ directory) is a different node in
   the new tree; the inode table never reuses an inode number, so no
   handle silently changes meaning. A handle to a removed path serves its
   captured identity until `release`.

## Resource bounds

All live-operation bounds (write budgets, mutation queue, parent
create tokens, open handles, demand admission, disk classification) are normative in
`resource-limits.md`; this section keeps only the write-path summary:

| Bound | Exceeded → |
|---|---|
| `write_per_handle_bytes` per dirty handle (default 64 MiB) | `ENOSPC` |
| `write_aggregate_bytes` aggregate across handles (default 256 MiB) | `ENOSPC` |
| `write_dirty_handles` (default 64) | `ENOSPC` |
| `max_pending_mutations` (default 4096, including the executing one) | `EAGAIN` |
| `max_parent_tokens` (default 4096 distinct parent paths) | `ESTALE` |

Buffered state is memory, so these are daemon-write budgets; overflow
fails closed rather than allocating without limit. Total open handles
are additionally capped (`max_open_handles`, default 4096,
`EMFILE` past it) — read captures pin their open-time version, so
the table is memory too — and retained capture bytes have their own
ceiling (`max_open_capture_bytes`, default 256 MiB, `ENOSPC` past
it, checked at open): a writable handle pins its capture plus its
commit base.

These budgets are local; they are independent of the **protocol
ingest limits** (`Limits::V0`), which still bound every committed object.
A mutation whose resulting file, tree, or manifest exceeds an ingest
ceiling is refused at the commit boundary (`EFBIG`), never committed as
an unrepresentable tree; the mount cannot be used to bypass
`check_tree`/`check_manifest`.

## Permissions and ownership (v0)

The mount is single-user. Reads present policy owner/group and mode bits
(as `wyrd-daemon` already does); writes are owned by the mounting
process. Files derive `0644` (`0755` with the exec bit); directories are
`0755`. Only the exec bit is represented. `chmod`-style requests update
the exec bit and **ignore unsupported bits**; `stat` always reports
Wyrd's canonical synthesized mode, so unsupported bits are accepted but
not persistent — stated explicitly so tooling does not believe a
permission change took effect. Owner/group and timestamps are accepted
and ignored (the format does not represent them). There are no ACLs.

## Errors

| Condition | errno |
|---|---|
| store, authoring, commit, or durability failure | `EIO` |
| store full (disk or quota) | `ENOSPC` |
| store not writable | `EACCES` |
| stale handle, conflicted heads | `EIO` |
| queued create parent replaced, rotated, or unavailable at admission | `ESTALE` |
| parent inode retired (kind change, committed removal) or re-minted during create admission | `ESTALE` |
| parent removal queued but unpublished during create admission | admitted; the loop settles the race (`ENOENT`/`ENOTDIR`/`ESTALE`) |
| `O_TRUNC` open whose path was replaced between the truncation and the open's capture | `ESTALE` |
| unsupported feature operation (symlink/link/xattr) | `EOPNOTSUPP` |
| name exists | `EEXIST` |
| name absent | `ENOENT` |
| component through a file | `ENOTDIR` |
| directory op on a file / file op on a directory | `EISDIR` / `ENOTDIR` |
| non-empty `rmdir` / replacing a non-empty directory | `ENOTEMPTY` |
| illegal rename (into descendant, trailing-slash mismatch) | `EINVAL` |
| offset + length overflow | `EFBIG` |
| mutation exceeds a protocol ingest ceiling (file/tree/manifest) | `EFBIG` |
| invalid range/argument | `EINVAL` |
| write/truncate on a handle without write access | `EBADF` |
| buffer/dirty-handle budget exceeded | `ENOSPC` |
| mutation queue full | `EAGAIN` |
| operation not implemented | `ENOSYS` |

`EOPNOTSUPP` and `ENOSYS` are distinct: `EOPNOTSUPP` means the operation
is **known and deliberately unsupported** by Wyrd v0 (symlink creation,
hard links, xattrs, `O_DIRECT`); `ENOSYS` means the FUSE handler does not
exist yet. The first is a policy contract, the second an implementation
gap.

## Layering (where the state machine lives)

The write state machine lives in the daemon and sync crates; FUSE stays
an adapter:

```text
presentation     wyrd-fuse (POSIX translation only)
                     ↓ reads the shared view; never authors
node             wyrd-core (MutationQueue, fold orchestration,
                 commit sequencing, stale checks, publication)
                     ↓ authors into
store            wyrd-sync (immutable tree mutation, snapshot
                 authoring, durable commit, announcement obligation)
```

Separately, the daemon backend owns the per-handle `WriteHandle`
state (buffers, base advance, budget release) and supplies the
post-commit transition as a handle-owner callback upward into the
orchestrated commit (rule 7). `wyrd-daemon` depends on `wyrd-core`,
never the reverse; `wyrd-fuse` depends on `wyrd-format` and
`wyrd-namespace` only and never calls into the node.

Stale checks, snapshot creation, tree mutation, and commit sequencing
must not be implemented inside FUSE callbacks.

## Non-goals (v0)

- No sparse files, hard links, symlink creation, xattrs, ACLs, mtimes,
  file locks, `mmap` writes, or `O_DIRECT`.
- No byte-range merging between handles: same-file stale handles fail
  (the append exception aside), and there is no three-way content merge.
- Write coalescing across handles follows the DG-1 boundary table
  above (one snapshot per forcing event, folding all pending).
- No automatic peer repair and no GC: superseded objects, manifests, and
  heads are retained append-only.
- No cross-device moves.
- No synthetic namespace entries for uncommitted state: `create` commits
  an empty file rather than exposing a pending name (architecture
  invariant 8).

## Test matrix

Each row locks a decided invariant.

**Lost-update boundary**

- **Stale writable handle**: A and B open one file; B commits; A commits
  → A gets `EIO`, B's content remains, no third snapshot. (Pre-fold
  mechanism: separate commits. Under DG-1, A goes terminal at B's
  fold, so "A commits" never happens — same outcome, earlier loss.)
- **Fold inverted case**: A and B hold dirty buffers on one file; B
  forces (`fsync`) → B wins the tie, B's bytes are durable on return,
  A's handle is terminal `EIO` before A ever calls. The explicit
  durability caller never loses to an earlier-buffered member.
- **Fold release tie-break**: A and B hold dirty buffers on one file;
  B closes → B's dirty release carries privilege, B wins, A's handle
  is terminal `EIO`.
- **Fold create tie-break**: A holds a dirty buffer on `P`;
  `open(P, O_TRUNC)` → the truncate carries privilege, the open
  succeeds and binds the just-committed identity, A's handle is
  terminal `EIO`. If the fold cannot be authored the open fails
  (`EIO`/`ESTALE`) with nothing committed.
- **Concurrent partial writes**: A edits range 0, B edits range 100 (both
  from one base) → exactly one commits; the other is stale, never a
  silent overwrite.
- **Different-path rebase**: A commits file X while B holds file Y
  → B commits onto A's head; both survive.
- **Append ordering**: A and B open `O_APPEND`; commits serialize as
  `old ‖ A ‖ B`.
- **Append versus an intervening writer**: `H0 foo=AAAA`; a normal writer
  commits `BBBB`; an append handle then commits `X` → `BBBBX` (observed,
  not rejected).
- **Append after removal**: append handle; another commit unlinks the
  target; append commits → `EIO`/`StaleHandle` (append never recreates).

**Handle lifetime**

- **Rename breaks a writable handle**: open `/a`, rename `/a`→`/b`, write
  the old handle, commit → `EIO` (`StaleHandle`); a read on the handle
  still serves the captured identity until `release`.
- **Unlink breaks a writable handle**: open `/a`, unlink `/a`, write,
  commit → `EIO`; the pre-unlink read capture still serves.
- **Kind change is stale**: open a file, replace it with a directory,
  commit → `EIO`.

**Mutation lifetime**

- **No post-timeout commit**: a request refused at admission (`EAGAIN`)
  never executes; a caller error is never followed by a later commit.
- **Queue total order**: M1 then M2 → M1's snapshot parent is H0, M2's
  parent is M1's snapshot.
- **Namespace versus predecessor**: `M1 mkdir(foo)` then `M2 mkdir(foo)`
  → M1 succeeds, M2 is `EEXIST`; each is evaluated against its
  predecessor's committed state, not the state at syscall entry.

**Commit boundaries**

- **Buffer, no commit**: `write` returns without a snapshot; same-handle
  read sees the overlay; the tree is unchanged until `flush`.
- **Single commit per flush**: N writes + one `flush` → one snapshot; a
  clean second `flush` commits nothing.
- **Close-time flush forces nothing for others**: a `flush` or
  `release` on a handle that never wrote commits nothing, even when
  another handle holds pending data on the same path; `fsync` on
  that path does commit it.
- **flush ≡ fsync durability**: a file survives a simulated restart
  after either; it may be lost after `write` without a commit boundary.
- **`O_SYNC` per write**: each successful `write` is durable before
  returning, in its own durable snapshot shared with any pending set.
- **`O_TRUNC`**: the truncation is visible to other opens immediately
  (it commits during open) and applies only to the file the open
  observed — a same-path replacement that lands first fails the open
  (`EIO`) with the replacement's content intact. A concurrent change
  after open makes the handle stale (`EIO`), while a truncate landing on
  a still-clean handle re-pins it.
- **`create` then content**: two snapshots, both roots readable; a crash
  after `create` leaves the empty file.
- **Failed commit is terminal**: after a stale/`EIO` commit the overlay is
  dropped; a second commit on the handle is refused rather than
  retrying the old buffer.
- **DG-1 fold (named to `wyrd-contracts`, implementation-gated)**:
  N writes across M handles and paths, plus effective namespace
  operations, inside one window produce **one** snapshot whose tree
  equals the final coherent state; `fsync` on a path with pending data
  forces the fold; `O_SYNC` stays durable per write; a committing
  boundary on a path with no pending data anywhere commits nothing;
  same-path concurrent members fail closed while different-path
  members rebase into the same snapshot; a multi-head drive refuses
  the fold with the documented errno; failure after the durable stage
  leaves the same durable state as before the attempt.
- **DG-1 negatives (named to `wyrd-contracts`, implementation-gated)**:
  the pending set populates no cache keyed on durable revision;
  appears in no manifest; satisfies no projection or transport
  serving request; creates no announcement obligation.

**POSIX surface**

- `O_APPEND`, `O_TRUNC`, `O_CREAT`, `O_EXCL`; `pwrite` beyond EOF
  (zero-fill); truncate grow/shrink/while-dirty; overlapping buffered
  writes; zero-length write; offset overflow (`EFBIG`); write to a
  directory (`EISDIR`); chmod exec bit; chmod unsupported bits (accepted,
  not persistent, stat unchanged).
- Rename matrix: file→file, file→dir, dir→empty, dir→nonempty,
  dir→descendant, same path, trailing slash, cross-directory.
- Directory-handle coherence: a `readdir` stream opened before a commit
  keeps its capture; a new `opendir` sees the change.
- Error timing: `write` on a read-only handle returns `EBADF`; a range
  overflow returns `EFBIG` from `write`, not from the commit; a commit
  that exceeds a protocol ingest ceiling returns `EFBIG` from
  `flush`/`fsync`.
- `EOPNOTSUPP` (deliberate) versus `ENOSYS` (handler missing).

**Failure at each stage**

- Object insertion fails; authoring fails; fact commit fails; publication
  fails; serving flush fails; announcement discharge fails. Each asserts
  the durable/visible/servable/obligation state from the pipeline section
  independently — and, because commit state is monotonic, that a later
  failure never rolls back an earlier durable state.
- **Serving gates announcement**: serving failure leaves the obligation
  recorded but undisclosed; a retry of serving then discharges it.
- **Outbox failure is survivable**: durable + visible + servable, the
  discharge fails, restart — the snapshot is rediscovered as
  un-discharged and announced.

**Resources**

- `MAX_WRITE_BUFFER_BYTES + 1` → `ENOSPC`, daemon memory bounded.
- `MAX_DIRTY_HANDLES + 1` → `ENOSPC`.
- `MAX_PENDING_MUTATIONS + 1` → `EAGAIN`.

**Conflicted drives**

- Write → `EIO` (`ConflictedHeads`); read still serves the merged view.
- Zero heads: the first `create`/`mkdir` authors an initial root and
  succeeds.

**Validation**

- A mutation that would produce an over-limit tree/manifest is refused
  (`EFBIG`) and never committed: the mount cannot bypass
  `check_tree`/`check_manifest`.

## Decision record (OD-1 / DG-1)

Decided: coalescing policy **A, independent of the POSIX mutation
unit, with dirty-handle release as a forcing event**. The rejected
alternative was **B, one snapshot per POSIX mutation** (today's
behaviour), which leaves the fixed per-snapshot overhead term in
`docs/storage-growth.md` unbounded. Release closes the window
because otherwise open/write/close churn defeats most of the
coalescing and the storage-growth term stays proportional to file
count rather than save events. No bounded idle window in v0.3: a
timer would commit without a caller-invoked durability boundary.
Namespace operations are folding forcing events; submissions that
resolve to no change submit and force nothing. Full options,
reasoning, and decider in `nostr:nevent1qqsgsh7jz4em9k8mzu9v46dyrsgpcvqlrm4ematxz3lra4r8zuyenwspz9mhxue69uhkwunpwdczuap49eehgu8xt8t`
(republish of
`nostr:nevent1qqspp78nadn9vyghn7hak7guydzxwquvy4av83qxc6hha476ky2lhlgpz9mhxue69uhkwunpwdczuap49eehgkxrkd3`).
