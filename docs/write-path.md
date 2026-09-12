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
                              4 publish the projection
                              5 flush serving residency
                              6 enqueue the announcement outbox
```

## Writable handles

One writable open handle owns one buffer; it is the only mutable write
state in the system. A handle captures:

- its **path** and the **base snapshot** it opened against;
- the **base file identity** — the tree entry's content at open (size,
  exec bit, ordered chunk ids) — the value the stale check compares;
- the **buffered overlay** (a logical file image, see below);
- its **open flags** (`O_APPEND` changes commit semantics);
- a **dirty** bit.

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
4. `O_APPEND` does not use the buffer offset: each buffered write is
   appended at the handle's current logical end, and the append is
   resolved against the **current** file end at commit time (below).

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
2. **Bounded.** At most `MAX_PENDING_MUTATIONS` requests may be queued;
   admission failure returns `EAGAIN`. The queue has its own lock, never
   the view's or the store's.
3. **Synchronous, no silent post-timeout commit.** Unlike a fetch want
   (which may outlive its waiter), a mutation has no wait timeout:
   admission is immediate (or `EAGAIN`), and once admitted the request
   either commits or fails before the caller returns. There is no path
   where `fsync` fails with `EIO` and the mutation nevertheless applies
   later. A wedged loop therefore blocks the caller, which is a daemon
   health failure bounded by the process supervisor — not a per-request
   cancellation.
4. **Publication is the same path as fetch.** A mutation applies under
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
identity (or its removal/type change) is stale. `truncate` and any
future handle-derived content mutation obey the same rule.

A stale or failed commit is **terminal for the handle**: the buffered
overlay is discarded and the committing boundary returns `EIO`; the
application must close and reopen (a transient store failure is not
retried with the old buffer, and the daemon keeps no per-handle error
state). A handle whose path was removed or replaced by an external
`unlink`, `rename`, or another handle's commit is stale in exactly this
sense: `write` still buffers into the overlay, and the divergence
surfaces at the committing boundary.

**`O_APPEND` is the explicit exception.** Append is position-independent,
so an append handle does not carry a content base to compare: its
buffered bytes are appended to the **current** head's file at commit
time. Two append handles therefore serialize in queue order and yield
`old ‖ A ‖ B`; neither loses. This is the only content mutation without a
stale check, and it exists because POSIX defines append against the
current end.

Namespace mutations (`mkdir`, `unlink`, `rmdir`, `rename`) carry no
handle base: they read-modify-write the current head under the queue's
total order.

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
   fact log are durable on this device. The fact-log commit is already
   append-only and crash-safe; the vault-directory fsync
   (`fix(sync): fsync the vault directory after publication`) and the
   object-store fsync path close the remaining gap.
4. **Publication.** Heads and materialization are swapped into the shared
   view under one short write lock. The view sees the old head until this
   step.
5. **Serving readiness.** The vault write-through to the serving mirror
   is flushed (`ServingEndpoint::flush`) so the new representations are
   servable by transport root.
6. **Announcement.** The snapshot is enqueued into the durable
   announcement outbox and announced asynchronously with retry
   (`feat(sync): durable announcement outbox and retry contract`).

**Durable at 1-3, visible at 4, servable at 5, propagated at 6.**

Failure at each stage, explicitly:

- **Before 3 (no durable commit):** no snapshot exists; nothing is
  published; the caller gets `EIO`; the previous head is untouched.
- **After 3, before 4 (durable but not projected):** the snapshot is
  durable and will survive a restart, but the view still serves the old
  head. The daemon's dirty bit forces republication on the next pass —
  the existing "a pass may commit durably before publication" invariant,
  inherited here, makes this recoverable rather than rollback territory.
- **At 5 (visible but not servable):** the new head is legitimate: local
  reads work from the object store, the snapshot stays durable, and
  **no announcement occurs**; peer fetches fail and retry, and the daemon
  retries serving. Serving failure is never a reason to roll back a
  durable, published snapshot.
- **At 6:** local commit and visibility stand regardless of announcement
  success; the outbox retries. Peer propagation is never part of local
  filesystem durability.

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
| `truncate` | The conceptual operation behind `setattr(size)`: materialize the file plaintext (path-scoped, through the normal demand path), re-chunk to the target size. Growing zero-fills; shrinking discards the tail. Obeys the stale-handle rule. |
| `set-exec` | The conceptual operation behind `setattr(mode)`: toggles the exec bit, the only mode state represented. |

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

This is a named cross-crate contract (a `wyrd-contracts` test), not
merely an implementation property.

## Open flags

| Flag | Semantics |
|---|---|
| `O_RDONLY` / `O_WRONLY` / `O_RDWR` | Access mode; a write handle is required for `write`/`truncate`. |
| `O_CREAT` | Create the file if absent (its own empty-file snapshot, per `create`). |
| `O_EXCL` | With `O_CREAT`, `EEXIST` if the name exists. |
| `O_APPEND` | Appends at the current end at commit time (see handles). |
| `O_TRUNC` | The handle's overlay starts **empty**; the truncation commits at the next `flush`/`fsync`/`release`, not at open. |
| `O_SYNC` / `O_DSYNC` | Accepted; every write takes the `fsync` path (a commit per write). |
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

New local resources need explicit bounds, matching the ingest and demand
limits elsewhere:

| Bound | Exceeded → |
|---|---|
| `MAX_WRITE_BUFFER_BYTES` per dirty handle | `ENOSPC` |
| `MAX_BUFFERED_BYTES` aggregate across handles | `ENOSPC` |
| `MAX_DIRTY_HANDLES` | `ENOSPC` |
| `MAX_PENDING_MUTATIONS` | `EAGAIN` |

Buffered state is memory, so these are daemon-write budgets; overflow
fails closed rather than allocating without limit.

These budgets are new and local; they are independent of the **protocol
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

**Mutation lifetime**

- **No post-timeout commit**: a request refused at admission (`EAGAIN`)
  never executes; a caller error is never followed by a later commit.
- **Queue total order**: M1 then M2 → M1's snapshot parent is H0, M2's
  parent is M1's snapshot.

**Commit boundaries**

- **Buffer, no commit**: `write` returns without a snapshot; same-handle
  read sees the overlay; the tree is unchanged until `flush`.
- **Single commit per flush**: N writes + one `flush` → one snapshot; a
  clean second `flush` commits nothing.
- **flush ≡ fsync durability**: a file survives a simulated restart
  after either; it may be lost after `write` without a commit boundary.
- **`O_TRUNC`**: open truncates nothing; the empty commit happens at the
  committing boundary.
- **`create` then content**: two snapshots, both roots readable; a crash
  after `create` leaves the empty file.
- **Failed commit is terminal**: after a stale/`EIO` commit the overlay is
  dropped; a second commit on the handle is refused rather than
  retrying the old buffer.

**POSIX surface**

- `O_APPEND`, `O_TRUNC`, `O_CREAT`, `O_EXCL`; `pwrite` beyond EOF
  (zero-fill); truncate grow/shrink/while-dirty; overlapping buffered
  writes; zero-length write; offset overflow (`EFBIG`); write to a
  directory (`EISDIR`); write after `unlink`; write after `rename`;
  chmod exec bit; chmod unsupported bits (accepted, not persistent, stat
  unchanged).
- Rename matrix: file→file, file→dir, dir→empty, dir→nonempty,
  dir→descendant, same path, trailing slash, cross-directory.
- Directory-handle coherence: a `readdir` stream opened before a commit
  keeps its capture; a new `opendir` sees the change.
- Error timing: `write` on a read-only handle returns `EBADF`; a range
  overflow returns `EFBIG` from `write`, not from the commit; a commit
  that exceeds a protocol ingest ceiling returns `EFBIG` from
  `flush`/`fsync`.

**Failure at each stage**

- Object insertion fails; authoring fails; fact commit fails; publication
  fails; serving flush fails; outbox enqueue fails; announcement fails.
  Each asserts the durable/visible/servable/propagated state from the
  pipeline section independently.

**Resources**

- `MAX_WRITE_BUFFER_BYTES + 1` → `ENOSPC`, daemon memory bounded.
- `MAX_DIRTY_HANDLES + 1` → `ENOSPC`.
- `MAX_PENDING_MUTATIONS + 1` → `EAGAIN`.

**Conflicted drives**

- Write → `EIO` (`ConflictedHeads`); read still serves the merged view.
- Zero heads: the first `create`/`mkdir` authors an initial root and
  succeeds.
