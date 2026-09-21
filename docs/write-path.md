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
                       │         │ flush / fsync / release
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
}
```

1. **Total order.** The queue establishes the total order of local
   mounted mutations; mutations execute serially in admission order.
   Submission order and execution order coincide, so snapshot parent
   selection is deterministic: each mutation's snapshot parents are the
   heads after the previous mutation.
2. **Bounded.** `MAX_PENDING_MUTATIONS` bounds all admitted, incomplete
   requests — including the request currently executing, not just those
   waiting. Admission beyond it returns `EAGAIN`. The queue has its own
   lock, never the view's or the store's. Shutdown closes admission:
   once the live loop stops, new submissions are refused with `EIO`
   (`Shutdown`) instead of queueing behind a loop that will never drain.
3. **Synchronous, no silent post-timeout commit.** Unlike a fetch want
   (which may outlive its waiter), a mutation has no wait timeout:
   admission is immediate (or `EAGAIN`), and once admitted the request
   either commits or fails before the caller returns. There is no path
   where `fsync` fails with `EIO` and the mutation nevertheless applies
   later.
4. **Liveness consequence (named).** The daemon synchronization loop is a
   hard liveness dependency for every committing FUSE operation: a wedged
   loop blocks the caller indefinitely. That is a daemon health failure
   bounded by the process supervisor, not a per-request cancellation, and
   it is the deliberate price of the no-post-timeout guarantee. Loop
   *exit* is different from a wedged loop: terminal error or shutdown
   resolves every admitted-but-incomplete request with `EIO`
   (`Shutdown`) instead of stranding it, and the closed queue refuses
   new submissions the same way.
5. **Publication is the same path as fetch.** A mutation applies under
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
is silently ignored. A path-addressed `truncate` on an open append handle
is likewise `EOPNOTSUPP`; an exec change through an append handle is a
path-addressed mutation.

Namespace mutations (`mkdir`, `unlink`, `rmdir`, `rename`, and
path-addressed `set-exec`) carry no handle base: they read-modify-write
the current head under the queue's total order, so each is evaluated
against the state its queue predecessor committed, never against the
state visible when the FUSE syscall began.

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
   snapshot must be announced.
4. **Publication.** Heads and materialization are swapped into the shared
   view under one short write lock. The view sees the old head until this
   step.
5. **Serving readiness.** The vault write-through to the serving mirror
   is flushed (`ServingEndpoint::flush`) so the new representations are
   servable by transport root.
6. **Announcement discharge.** The recorded obligation is sent
   with retry through the durable outbox (`Engine::announce_snapshot`
   for one snapshot, `Engine::announce_pending` for the resume path:
   per-recipient delivered markers, byte-identical sealed retries).

**Objects prepared at 1; authoring prepared at 2; durable at 3 (with the
announcement obligation recorded); visible at 4; servable at 5;
obligation discharged at 6.**

### Commit state is monotonic (invariant)

> Later-stage failure never rolls back an earlier durable state.

The state machine is monotonic: `prepared → durable → visible →
servable → obligation recorded → discharged`. A failure at a later stage
leaves the earlier states standing; nothing after step 3 undoes step 3.
This is what forbids transactional coupling between the local commit and
network propagation.

### Announcement obligation durability

The obligation to announce a locally authored snapshot is **created at
step 3, atomically with the commit**, not at step 6. Step 6 only
*discharges* it. Therefore outbox-enqueue failure cannot lose an
announcement: if step 3 committed, the obligation is durable, and a
restart reconciles un-discharged obligations back through the outbox
(`Fact::AnnouncementQueued` / `AnnouncementSealed` /
`AnnouncementDelivered`; pending derives as queued-minus-delivered).
The outbox entry is eligible for discharge only once serving readiness
(step 5) has succeeded for that snapshot — eligibility is
composer-ordered (announce after flush), not engine-gated.

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

`flush` and `fsync` are **semantically equivalent** for Wyrd's durability
guarantee: there is no cached-but-not-durable commit state — the commit
boundary *is* the durability boundary. They differ only in how
applications observe the result: `flush` runs on every `close` and its
error is frequently ignored, so `fsync` is the reportable persistence
point. A committing boundary on a **clean** handle performs no snapshot.

Because `release` is best-effort and drops the buffer, an application
that never calls `flush`/`fsync` can lose acknowledged writes. This is
standard POSIX-without-`O_SYNC`: `write` is not durable. The mount states
it plainly.

`O_SYNC`/`O_DSYNC` deliberately sacrifice write coalescing: because the
unit of commit is the snapshot, each successful `write` on such a handle
is its **own durable snapshot** (a committing boundary per syscall). That
is expensive and correct by construction.

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
  commit will.

## Namespace operations

Each operation is one snapshot unless stated otherwise. `sqlite`-style
multi-step tooling is unaffected: each committed state is a complete,
valid filesystem.

| Operation | Semantics (v0) |
|---|---|
| `create` | Creates an empty regular file as its own snapshot **and** returns a handle based on the resulting snapshot, as one daemon operation (no window between them). The empty-file snapshot is a complete, independently valid state: a crash before the first content commit leaves it, and a peer may observe it. `O_EXCL` → `EEXIST`. |
| `write` | Buffer only; committed by `flush`/`fsync`/`release`. |
| `mkdir` | Creates an empty directory. Does **not** create intermediates: `mkdir a/b/c` is `ENOENT` when `a/b` is absent. `EEXIST` when the name exists. (The mount does not inherit `Daemon::put_file`'s intermediate-creation convenience.) |
| `unlink` | Removes a file or symlink entry; `EISDIR` on a directory; `ENOENT` when absent. |
| `rmdir` | Removes an empty directory only (`ENOTEMPTY` otherwise); `ENOTDIR` on a file. |
| `rename` | File→file replaces; file→dir `EISDIR`; dir→empty-dir replaces; dir→nonempty-dir `ENOTEMPTY`; dir→file `ENOTDIR`; a directory into its own descendant `EINVAL`; same path is a no-op. A trailing slash on the source requires a directory. |
| `truncate` | The conceptual operation behind `setattr(size)`: construct the new file representation at the target size. Growing preserves the existing bytes and zero-fills; shrinking preserves the prefix and discards the tail. Obeys the stale-handle rule. |
| `set-exec` | The conceptual operation behind `setattr(mode)`: toggles the exec bit, the only mode state represented. |

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
a target it names. Paths are handled as canonical components, not raw
strings.

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
| `O_CREAT` | Create the file if absent (its own empty-file snapshot, per `create`). |
| `O_EXCL` | With `O_CREAT`, `EEXIST` if the name exists. |
| `O_APPEND` | Appends at the current end at commit time (see handles); the target must remain a regular file. |
| `O_TRUNC` | The handle's overlay starts **empty**; the truncation commits at the next `flush`/`fsync`/`release`, not at open. It captures the opened file's base identity and **obeys the normal stale-handle rule**: if another commit changed the file before the truncation commits, the handle is stale (`EIO`). |
| `O_SYNC` / `O_DSYNC` | Accepted; every write is its own durable snapshot (see flush/fsync). |
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
bootstrap `Daemon::put_file` performs), so `create`/`mkdir`/`write` on an
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

All live-operation bounds (write budgets, mutation queue, open
handles, demand admission, disk classification) are normative in
`resource-limits.md`; this section keeps only the write-path summary:

| Bound | Exceeded → |
|---|---|
| `write_per_handle_bytes` per dirty handle (default 64 MiB) | `ENOSPC` |
| `write_aggregate_bytes` aggregate across handles (default 256 MiB) | `ENOSPC` |
| `write_dirty_handles` (default 64) | `ENOSPC` |
| `max_pending_mutations` (default 4096, including the executing one) | `EAGAIN` |

Buffered state is memory, so these are daemon-write budgets; overflow
fails closed rather than allocating without limit. Total open handles
are additionally capped (`max_open_handles`, default 4096,
`EMFILE` past it) — read captures pin their open-time version, so
the table is memory too.

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
wyrd-fuse        POSIX translation only
                     ↓
wyrd-daemon      WritableHandle, MutationQueue, commit orchestration,
                 stale checks, publication
                     ↓
wyrd-sync        immutable tree mutation, snapshot authoring,
                 durable commit, announcement obligation
```

Stale checks, snapshot creation, tree mutation, and commit sequencing
must not be implemented inside FUSE callbacks.

## Non-goals (v0)

- No sparse files, hard links, symlink creation, xattrs, ACLs, mtimes,
  file locks, `mmap` writes, or `O_DIRECT`.
- No byte-range merging between handles: same-file stale handles fail
  (the append exception aside), and there is no three-way content merge.
- No write coalescing across handles.
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
  → A gets `EIO`, B's content remains, no third snapshot.
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
- **flush ≡ fsync durability**: a file survives a simulated restart
  after either; it may be lost after `write` without a commit boundary.
- **`O_SYNC` per write**: each successful `write` produces its own
  durable snapshot before returning.
- **`O_TRUNC`**: open truncates nothing; the empty commit happens at the
  committing boundary; a concurrent change to the file makes the
  truncation commit stale (`EIO`).
- **`create` then content**: two snapshots, both roots readable; a crash
  after `create` leaves the empty file.
- **Failed commit is terminal**: after a stale/`EIO` commit the overlay is
  dropped; a second commit on the handle is refused rather than
  retrying the old buffer.

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
