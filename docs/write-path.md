# The Mounted Write Path

Normative design for writing through the mount: how POSIX mutations map
onto immutable snapshots, when a change is durable versus visible versus
announced, and what the mount refuses. It is the write-side companion to
`fetch-on-open.md` (the read side), and it exists so the write work
implements a stated contract instead of designing against the tracker.

Tracking issues (titles; fetch nevents with `ngit issue list`):

- `docs(write-path): design the mounted write path`
- `feat(format): mkdir, rmdir, and rename mutations`
- `feat(fuse): mounted write operations`

Landing order: this doc → format mutations → FUSE write operations. The
composition seam (`refactor(daemon): make runtime ownership and
projection publication explicit`), projection-generation caches, and the
announcement outbox land as their tracked issues require; the mount can
commit locally before the outbox exists, but peer propagation is not "end
to end" until it does.

## The core tension

POSIX writes are byte-range, in-place, incremental, and per-descriptor.
Wyrd is immutable and content-addressed: a change is not a mutation of
existing bytes, it is a **new snapshot over a new root**, and heads are
the drive's state. There is no in-place write to map a `pwrite` onto.

The design consequence is stated once and accepted everywhere below:

> the unit of commit is the snapshot, not the byte range.

Every committing operation is a read-modify-write of the whole tree:
materialize the live tree, apply the change in the object store, author
and durably commit a snapshot, publish it. Byte ranges buffer above that;
they never reach the protocol.

```text
POSIX op            mount                       drive
─────────           ─────                       ─────
write(fd, off,..)   buffer per handle           (nothing)
flush/fsync/        submit mutation ──► loop ──► put + author + commit
release                                          + publish (new head)
create/mkdir/...    submit mutation ──► loop ──► one snapshot
```

## The write session

One writable open handle owns one buffer; the buffer is the only mutable
write state in the system.

1. **`write(offset, data)` buffers and returns.** It does not touch the
   engine, the store, or the view. A write beyond the current end
   zero-fills the gap: sparse files are not representable (see
   non-goals), so a hole materializes as zeros.
2. **Reads on the same handle observe the buffer** (read-your-writes).
   Reads on other handles, and new opens, observe the last committed
   head — the read side's open-time capture is unchanged.
3. **`flush`, `fsync`, and `release` commit.** They materialize the
   buffer as one whole-file mutation and block until the daemon commits
   it. `flush` is called on every `close`; `fsync` additionally
   guarantees device-local durability before returning; `release` is
   best-effort (its error is usually discarded by applications, so
   `fsync` is the reliable report point). A second commit with no dirty
   buffer is a no-op.
4. **The commit re-chunks the whole file.** Chunking is content-defined;
   a one-byte change near the front may rewrite most chunk objects, and
   every commit seals a fresh representation (fresh AEAD nonces). This
   is the accepted cost of immutable, unlinkable representations.
5. **Buffered bytes are not durable until `fsync`/`flush`.** A crash
   between `write` and `flush` loses them, exactly as POSIX permits
   (`write` semantics with no `O_SYNC`). The mount does not claim
   otherwise.

## Submitting mutations: the engine stays the single authority

`fetch-on-open.md` establishes that FUSE never calls the engine, the bulk
source, or the store — it registers demand and waits. The write path is
symmetric:

1. **FUSE never authors.** A committing operation submits a `Mutation`
   to the daemon's mutation queue and blocks on its completion, with the
   same bounded wait and `EIO` on expiry as a fetch want.
2. **The loop applies mutations.** The live loop is the only engine
   user: it drains the mutation queue each pass, applies the tree
   mutation in the object store, authors the snapshot, commits the
   facts, and publishes. This preserves "one synchronization authority"
   and reuses the publication path fetch already uses (heads and
   materialization swapped under one short view write lock).
3. **A materializing mutation wakes the loop.** It must not wait for the
   idle poll interval: the submission signals the loop's wake channel,
   and a commit completes in authoring time. (The read-side want path
   polls today; unifying both on the wake is part of the event-driven
   sync work, but `fsync` cannot be poll-bound.)
4. **The rejected alternative:** sharing the engine behind a mutex with
   the FUSE thread. It would make commits synchronous without a queue,
   but it dissolves the single-authority discipline, puts engine commits
   in contention with intake and fetch, and complicates the loop's
   dirty/republication invariant. The queue keeps the lock story
   unchanged.
5. **Locking.** The mutation queue has its own lock, never the view's or
   the store's. Applying a mutation takes the store-write path and the
   short view write lock for publication; neither is ever held across a
   waiter wait.

## Commit pipeline and durability ordering

A commit proceeds in this order, and the order is the contract:

1. **Objects.** The chunks and rebuilt tree nodes for the new root are
   inserted into the content-addressed store. Immutable and idempotent;
   re-inserting identical content is a no-op.
2. **Authoring.** `Engine::author_snapshot` seals the manifest hierarchy
   from representations the device holds, imports the sealed envelopes
   and the signed snapshot body into the durable vault, and commits the
   snapshot-body and manifest facts.
3. **Local durability.** `fsync`/`fsync`-eligible `flush` returns only
   after the object store, the vault, and the fact log are durable on
   this device. The fact-log commit is already append-only and
   crash-safe; the vault-directory fsync
   (`fix(sync): fsync the vault directory after publication`) and the
   object-store fsync path close the remaining gap.
4. **Publication.** Heads and materialization facts are swapped into the
   shared view under one short write lock, exactly as a fetch pass
   publishes. There is no partial publication: the view sees the old
   head until this step, and a commit that fails earlier publishes
   nothing (the loop's dirty bit forces republication on the next pass).
5. **Serving readiness.** The vault write-through to the serving mirror
   is flushed (`ServingEndpoint::flush`), so the new representations are
   servable by transport root before the address is announced.
6. **Announcement.** The new snapshot is enqueued into the durable
   announcement outbox and announced asynchronously with retry
   (`feat(sync): durable announcement outbox and retry contract`). The
   local ack does not wait for peers.

So: **durable at 1-3, visible at 4, servable at 5, propagated at 6.**

## Namespace operations

Each operation is one snapshot unless stated otherwise.

| Operation | Semantics (v0) |
|---|---|
| `create` | Creates an empty regular file as its own snapshot. The name exists immediately (one source of truth); the following content commit is a second snapshot. The extra snapshot per new file is accepted. |
| `write` | Buffer only; committed by `flush`/`fsync`/`release`. |
| `mkdir` | Creates an empty directory (`feat(format)` primitive). `EEXIST` when the name exists. |
| `unlink` | Removes a file or symlink; `EISDIR` on a directory; `ENOENT` when absent. |
| `rmdir` | Removes an empty directory only (`ENOTEMPTY` otherwise); `ENOTDIR` on a file. |
| `rename` | File→file replaces; file→dir `EISDIR`; dir→empty-dir replaces; dir→nonempty-dir `ENOTEMPTY`; dir→file `ENOTDIR`; moving a directory into its own descendant `EINVAL`; same path is a no-op. One snapshot, so readers see the old or the new root, never a mix. |
| `setattr` size | Materializes the file plaintext (through the normal demand path, bounded) and re-chunks to the new size. Growing zero-fills; shrinking discards the tail. No sparse representation. |
| `setattr` mode | Only the exec bit is represented: `chmod`-style changes toggle it. All other mode bits, owner/group, and timestamps are accepted and ignored — the format does not represent them (`object-model.md`), and refusing them breaks ordinary tooling. |
| `flush` | Commits the handle; no-op when clean. |
| `fsync` | Commits and waits for device-local durability. |
| `release` | Commits best-effort; always drops the handle and buffer. |

`create`, `mkdir`, `unlink`, `rmdir`, `rename`, and size-changing
`setattr` commit immediately; they do not wait for `flush`.

## Conflicted drives

A path mutation is a read-modify-write of **one** tree. The daemon's
`live_base` therefore requires exactly one eligible live head; with more
than one, mount writes fail closed with `EIO` (`WriteError::Conflicted`).

This is deliberate, and it does not conflict with `epochs.md`'s "local
write" rule (a member may publish a snapshot parenting onto any subset of
heads): that rule authorizes a device to *resolve* a conflict by
publishing a snapshot whose parents are all heads. Resolution is not a
path mutation and has no mount surface in v0. The mount reads the merged
view (both heads) and refuses to write until the drive is resolved by
other means; resolution UX is future work.

## Coherence

1. Every commit advances a **projection generation**. The backend's
   directory and inode caches revalidate against it on the next
   operation (`feat(fuse): make directory and inode caches
   projection-generation aware`). Without this, `readdir` after a write
   can serve a stale directory.
2. Reads keep the read side's **open-time capture**: a descriptor serves
   the identity it opened. A commit does not retarget existing
   descriptors; the next `open` sees the new head.
3. An entry whose kind changed (file ↔ directory) is a different node in
   the new tree; the inode table never reuses an inode number, so no
   handle silently changes meaning. A handle to a removed path serves
   its captured identity until `release` (POSIX permits the
   unlinked-open-file behavior).

## Permissions and ownership (v0)

The mount is single-user: reads present policy owner/group and mode bits
(`wyrd-daemon` already does this) and writes are owned by the mounting
process. Files derive `0644` (`0755` with the exec bit); directories are
`0755`. There are no ACLs, no owners other than the mounter, and no
per-file credentials in the format.

## Errors

| Condition | errno |
|---|---|
| store, authoring, commit, or durability failure | `EIO` |
| wait deadline expired | `EIO` |
| conflicted live heads | `EIO` |
| name exists | `EEXIST` |
| name absent | `ENOENT` |
| path component through a file | `ENOTDIR` |
| directory operation on a file / file operation on a directory | `EISDIR` / `ENOTDIR` |
| non-empty `rmdir` / replacing a non-empty directory | `ENOTEMPTY` |
| illegal rename (into own descendant, etc.) | `EINVAL` |
| operation refused by policy (symlink creation, hard links, xattrs) | `EROFS` |
| operation not implemented | `ENOSYS` |

## Non-goals (v0)

- No sparse files, hard links, symlink creation, xattrs, ACLs, mtimes,
  file locks, `mmap` writes, or `O_DIRECT`.
- No write coalescing across handles, and no cross-device moves.
- No automatic peer repair and no GC: superseded objects, manifests, and
  heads are retained append-only.
- No merging: concurrent device writes produce multiple heads, surfaced
  on read and refused on write (above).
- No synthetic namespace entries for uncommitted state: `create` commits
  an empty file rather than exposing a pending name, keeping the view a
  projection of committed snapshots (architecture invariant 8).

## Test matrix

Each row locks a decided invariant and becomes a test.

- **Buffer, no commit**: `write` returns without a snapshot; the same
  handle reads its own bytes; the tree is unchanged until `flush`.
- **Single commit per flush**: N writes + one `flush` produce one
  snapshot; a clean second `flush` commits nothing.
- **fsync durability**: the file survives a simulated restart after
  `fsync`; it may be lost after `write` without `flush`.
- **create then content**: `create` yields an empty-file snapshot;
  `write`+`flush` yields a second; both roots remain readable.
- **Namespace semantics**: every row of the operation table, including
  the errno table.
- **Rename atomicity**: one snapshot; a concurrent reader observes the
  old or the new root, never a partial mix.
- **Conflicted heads**: write returns `EIO`; read still serves the
  merged view.
- **Commit failure publishes nothing**: an injected store/commit failure
  leaves the view and heads unchanged; a retry succeeds.
- **Cache coherence**: `readdir` after a committed write shows the new
  entry on the next open.
- **Cross-handle visibility**: a second handle sees a writer's bytes
  only after the writer commits.
- **Serialized commits**: two handles' commits land as two snapshots in
  submission order.
- **Ordering**: a representation is never servable before its vault
  residency, and an announcement is never emitted before local
  durability.
- **Policy refusals**: symlink/hardlink/xattr requests return `EROFS`;
  unimplemented ops return `ENOSYS`.
