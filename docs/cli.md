# `wyrd` CLI reference

The `wyrd` process host (`crates/wyrd-cli`): argument parsing,
credential files, mount orchestration, diagnostics, and exit codes
over the daemon's public surface. It never implements drive logic
itself — every subcommand opens the drive through `WyrdNode` and the
behavior lives in `wyrd-core` / `wyrd-daemon`. This document mirrors
`crates/wyrd-cli/src/main.rs`; when they disagree, the code wins and
this document is stale.

## Subcommands

```
wyrd init --identity-file <path> --passphrase-file <path> <drive_dir>
wyrd mount [--relay <url>...] [--verbose] \
    --identity-file <path> --passphrase-file <path> <drive_dir> <mountpoint>
wyrd export --identity-file <path> --passphrase-file <path> <drive_dir> <out_dir>
wyrd member --identity-file <path> --passphrase-file <path> <drive_dir> (list | log | status | remove <device> [--yes] | rotate | set-owner <device> | invite <device> <encryption-key> <out> [--reader] | reissue-invitation <device> <out>)
wyrd device --identity-file <path> --passphrase-file <path> <drive_dir> (id | pairing-request <out> | join <invitation>)
wyrd sync [--relay <url>...] --identity-file <path> --passphrase-file <path> <drive_dir> (status | now)
```

### `init` — create a drive

Writes the drive's keystore and object store under `<drive_dir>`:
identity, root custody, genesis membership. Idempotent only in the
sense that re-running refuses — init never merges into an existing
drive.

### `mount` — serve a live read-write projection

Serves the drive's live projection at `<mountpoint>` via FUSE until
SIGINT/SIGTERM, which tears down in order: unmount and session join
first (`destroy` commits still-dirty handles against the still-open
mutation queue), then admission close and the loop join, then
transport (mailbox, bulk source, serving) under bounded deadlines.
A process holding a file open on the mount delays the session join
until it closes — unmount refuses a busy mount — so SIGINT waits
for the last descriptor; the stop budgets bind the unmount itself,
not a wedged holder.
Writes through the mount commit as snapshots; the
serving endpoint and bulk source stay up for the life of the mount so
peers can fetch what this drive holds.

- `--relay <url>` (repeatable): control-plane relays. With none
  given, control-plane intake stays idle and the drive is local-only —
  mounts still serve local state.
- `--verbose`: debug-level FUSE request logs (opcode, latency, reply
  errno) on stderr and in `mount.log`. Without it the mount logs at
  info level.

On macOS the mount preflights the macFUSE runtime before binding any
endpoint: a missing kext or mount daemon fails fast with the checklist
next to the raw error (whose errno may be stale — macFUSE's libfuse2
mount can fail without setting errno).

### `export` — materialize a plain copy

Writes the drive's namespace to `<out_dir>` as an ordinary directory
tree: files, directories (empty ones included), symlinks, and the
executable bit (0o755 vs 0o644). The output needs no wyrd software to
read afterward — this is the offline egress path guaranteed before
any format break.

- Offline by construction: no `--relay` flag exists, and export never
  touches relays, the mailbox, the serving endpoint, or FUSE.
  Content the device does not hold fails the export closed, naming
  the missing bytes — a partial tree that silently drops files is
  worse than no tree.
- Multi-head conflicts export as `name@N` siblings, numbered in
  SnapshotId byte order — the same numbering the mounted `foo@N`
  grammar selects by. Export never picks a winner silently.
- Symlinks remain representable in the drive, but mounted FUSE views do
  not provide transparent symlink traversal in v0: `readlink` fails with
  `EOPNOTSUPP` because a host pathname walk can span live projection
  generations. Offline export uses one immutable view and emits only
  links whose complete target is statically confined; absolute targets,
  root escapes, conflicts, cycles, and hop/work-limit failures are
  refused. Export permits at most 40 followed links and 256 expanded
  components per link, plus a 64 MiB weighted resolution-work budget
  (tree reads are charged by encoded bytes) shared across the export,
  while the plain copy stays self-contained.
- `<out_dir>` must not exist or must be empty; export never merges
  into a populated tree. The walk lands in a uniquely named staging
  sibling and renames it into place only after the whole tree
  succeeds, so a failed export leaves no partial tree behind. Each
  run heartbeats its staging; a later export sweeps staging that
  proves exporter ownership (exact generated name plus a valid
  heartbeat marker) with a heartbeat older than an hour, and leaves
  everything else — live runs, user directories, marker-less
  leftovers — alone or for manual cleanup. Concurrent exports to
  the same destination race to publish: the first rename wins and
  later ones fail with a populated destination — the destination
  always holds one complete tree, never a mix.

### `member` — administer drive membership

Reads project the membership log offline over the keystore; writes
author one transition plus catch-up obligations through the engine,
which enforces owner-only — the CLI never decides authorization
itself. Catch-up delivery to other devices happens on the next
mounted sync via the mailbox, not here. Devices are 64 hex
characters (x-only pubkeys).

- `list`: members, owners, and readers at the canonical tip, one identity per
  line under an `epoch <n> tip <id>` header.
- `log`: every observed transition in epoch order with its
  canonical status (`canonical`, `contested`, `voided`, `orphaned`,
  `pending`, `invalid:<reason>`) and author; frozen conflict epochs
  are marked.
- `status`: known tip epoch and id, member/owner counts, frozen
  state, and held epoch secrets. Knowledge is not possession: a
  known epoch without its secret authorizes nothing until the
  capability arrives. A frozen conflict epoch lists its rival tips —
  the live contenders the epoch waits on.
- `resolve <winner> --void <sibling>...`: resolve a frozen
  membership conflict (owner-only) by naming the winning tip and
  exactly the voided siblings. The engine proves the closed
  resolution — every id a live contender at the frozen epoch, the
  void set exactly the winner's rivals, owner authority in the
  pre-transition state — before authoring; anything less fails
  closed with no transition. The carry obligations staged ahead of
  authoring still commit on a refusal — benign: the next drain
  discharges them without authoring while the heads stay eligible.
- `remove <device>`: author a removal transition. The removed device —
  member or reader — receives no new-epoch material; its acquisition
  ends at the removal boundary while its history stays valid.
  Removing the sole owner is valid but terminal — it empties the owner
  set and no future transition can be authorized — so it requires
  `--yes`. Like `rotate` and `set-owner` below, `remove` fails on a
  membership-frozen drive with "transition leaves a membership
  conflict frozen; resolve it first": nothing new is canonical while
  frozen, so the conflict resolves before any of the three commits.
- `rotate`: force a fresh epoch secret. Membership unchanged; every
  current member and reader is owed the new-epoch wrap.
- `set-owner <device>`: hand ownership to a member (v0 ownership is
  a singleton). Authority comes from the pre-transition owner set,
  so the current owner signs the handover.
- `remove`, `rotate`, `set-owner`, and `invite` carry the namespace
  forward: after the transition commits, each served head is
  re-authored at the new epoch over the same tree (transition
  continuity, `epochs.md`), so a quiet drive keeps serving its files
  and the next write extends the carry. A transition on an empty
  drive carries nothing; the reported `(N carried)` names the count.
- `invite <device> <encryption-key> <out> [--reader]`: admit a device
  and write its sealed invitation to `<out>` for out-of-band delivery.
  The transition commits with the usual catch-up obligations; the
  newcomer joins from the invitation file. With `--reader` the device
  joins read-only: it holds every epoch secret but authors nothing.
  The destination is claimed before the commit: an existing file is
  refused, and an uncreatable path fails with no transition authored.
  A write failure past the commit leaves the admission standing —
  recover with `reissue-invitation` below instead of re-inviting
  (which reports `AlreadyMember` — or `AlreadyReader`).
- `reissue-invitation <device> <out>`: reseal a device's invitation
  from durable state, for an admission whose invitation never
  reached a file. Authors nothing; the reseal opens identically,
  with fresh randomness. Owner-only, like admission, and only for
  an active canonical member or reader: revocation bounds
  acquisition, so a removed device's lost invitation stays lost, and a
  valid-but-noncanonical branch never anchors a grant. Same
  destination policy as `invite`.

Membership state beyond the CLI: device identity is single-use
within a membership chain — a removed device returns only under a
fresh identity (`docs/epochs.md`).

### `snapshot` — inspect snapshots and merge conflicted heads

Reads project the snapshot DAG offline over the keystore; a merge
authors one snapshot with ordinary member authority through the
engine, which enforces head eligibility and the merge-spec contract
— the CLI never decides authorization itself. Announcements for the
merge queue with the usual outbox, delivered on the next mounted
sync. Head references are `@N` over the *selected* heads in ascending
SnapshotId order — head-wise, not path-wise. The mount and export
number the versions of one path (`name@N`), skipping heads that lack
the path, so a present-vs-absent conflict's `@N` there is not the
merge's `@N`. And with `--head` narrowing, `@N` counts the selection,
not the full live-head set: re-check the numbers before copying them
from `snapshot list` into a narrowed merge.

- `list`: the live heads with their `@N` numbers, epochs, authors,
  trees, and parent counts.
- `heads`: every DAG head with its authorization classification
  (`eligible`, `canonical-history`, `superseded`, `stranded`,
  `voided`, `pending:<reason>`, `rejected:<reason>`) and epoch.
  Eligible heads carry their `@N` merge numbers; every other class
  is retained history with its reason attached.
- `merge [--head <id>...] [--default @N] [--take path=@N]...
  [--drop path]...`: merge source heads — all live heads by
  default, or an explicit subset of at least two — into one
  snapshot parented onto exactly the selected heads at the current
  epoch. The merged tree is a deterministic function of the
  sources plus the spec: paths every source agrees on take
  themselves, conflicted root paths take `--take path=@N`, drop
  with `--drop path`, or fall back to `--default @N`. A spec line
  on an agreed path, a path no source holds, an uncovered conflict,
  or a source whose bytes are not locally servable all fail closed
  with nothing committed. A short selection with no eligible heads
  on a membership-frozen drive is refused with a pointer to `member
  resolve`, since the conflict snapshots park as pending; a frozen
  drive carrying a genuine pre-conflict fork still merges, binding
  the still-canonical pre-conflict tip. No membership change, no
  epoch change.
  The choice is one-way from the CLI: the unselected versions
  survive only inside the merge's parent heads, which no v0 surface
  reads back.
- `plan [--head <id>...]`: preview a merge without authoring —
  one row per root path over the same `@N` basis, naming each
  head's version, so the operator sees which paths are agreed and
  which need a `--take` line before merging. Refused with a pointer
  to `member resolve` where a short selection meets no eligible
  heads on a membership-frozen drive.

### `device` — pair this device with a drive

The local-device half of multi-device setup. Pairing and join are
offline file exchanges; the drive directory holds the staged secret
and (after join) the member custody record. Catch-up arrives on the
next mounted sync, not here.

- `id`: this device's id plus the encryption key the membership
  state registers for it. `unregistered` is honest, not an error: a
  fresh join holds genesis only, and its own admission arrives with
  the catch-up set. Also the cheapest reopen probe — it opens the
  keystore, which works for owner and member records alike.
- `pairing-request <out>`: stage this device's pairing secret and
  write the public pairing material (device plus encryption key, no
  secrets) to `<out>` for the owner. Re-running returns the same
  key: the owner may already have admitted it.
- `join <invitation>`: join from the owner's sealed invitation.
  Member custody persists before the accept commits, so the device
  reopens afterwards. A pairing for another key, a truncated or
  forged invitation, or a join without pairing all fail closed, and
  a refused join writes nothing. Join never targets an owner's
  drive home or another device's member directory: an owner record
  refuses outright, and a member record for another device refuses
  rather than stranding it.

The pairing flow, end to end:

```
# newcomer, in its own directory
wyrd device --identity-file ... --passphrase-file ... <newcomer-dir> pairing-request pairing.txt
# owner, with the pairing material
wyrd member --identity-file ... --passphrase-file ... <owner-dir> invite <device> <encryption-key> invitation
# newcomer, with the invitation file
wyrd device --identity-file ... --passphrase-file ... <newcomer-dir> join invitation
```

### `sync` — headless sync without mounting

The two commands have deliberately different contracts:

```text
sync status
    = durable observation
    = never connects, sends, drains, or touches the seen log
    = never mutates the outbox or materialization
    = needs the drive un-mounted (exclusive store lock)

sync now
    = bounded synchronization run
    = connects
    = may mutate durable state
    = reports network liveness
    = either converges or explicitly reports incomplete
```

- `status`: pending outbox obligations with their queued,
  delivered, and pending split (announcements per snapshot,
  transitions per transition id, capabilities per epoch), the known
  membership tip against held epoch secrets (knowledge is not
  possession), live heads with classification counts over every DAG
  head, and mailbox posture. Read-only against durable state only:
  with no `--relay` the mailbox reads idle, and with relays it
  reports the configured count — status never connects, so there is
  no liveness to show and no seen log, delivery mark, outbox
  discharge, or retry mutation to make. Liveness belongs to `now`
  and `mount`. Two precise limits: opening the keystore can commit
  owner-bootstrap resume facts (an interrupted genesis, the
  self-capability install), so "never mutates" means no intake, no
  send, no seen log, and no outbox or materialization mutation —
  not zero writes in every corner; and the store lock is exclusive,
  so status needs the drive un-mounted and fails closed with the
  lock error while a mount holds it.
- `now`: runs the mount's sync machinery (drain, deliver,
  announce, fetch through `sync_once`) with the mount's live
  budgets and no FUSE session: vaults and NAS replicas converge
  without mounting. Stops on the first quiet pass and prints pass
  and intake/fetch totals with the obligations still pending.
  At most 32 passes: a peer that keeps intake non-idle forever
  (which a mount absorbs by running forever) trips the cap, which
  reports `stopped: pass limit (32) reached; sync may be
  incomplete` and exits non-zero — a capped run is never reported
  as converged. A run that stops with known-but-unfetchable heads
  exits zero: the outbox is empty and there is nothing local left
  to do, so a non-zero exit would only invite pointless retries —
  automate on the `unfetchable heads` count, not the exit status,
  when that distinction matters.
  Quiet is never trusted on first sight: relay delivery races the
  first drain, so a quiet verdict parks a short settle window
  (arrival short-circuits it) and confirms with a second pass.
  A head whose closure is not local is a remote
  condition, not local work: after one grace pass it stops the run
  as quiet with an explicit `N unfetchable heads` count instead of
  burning the cap. Zero-progress passes park the settle window too,
  so dead churn waits on the relay instead of spinning.
- `--relay <url>` (repeatable, shared parsing with `mount`): with
  none given, intake stays idle and `now` discharges local
  obligations and fetches nothing new.

Route-less authoring is intentional, not an omission: `now` binds
no serving endpoint, so its announcements carry no retrieval
route. A snapshot authored or fetched headless is announced as
known-but-unfetchable — peers learn it through intake (which
accepts the announcement) and report absence (never corruption)
until a route arrives. Mounting later publishes the route through
the normal route-update path and the content becomes serveable.
A headless process is never left reachable after the command
exits, advertises no address, and creates no new durable serving
obligation.

## Credential files

All subcommands take `--identity-file` and `--passphrase-file`.
Both are read and hardened by wyrd code, never by clap:

- The identity file holds exactly 32 raw bytes or 64 hex characters
  (whitespace-trimmed); anything else is rejected.
- The passphrase file holds UTF-8 text with one trailing newline
  stripped; files over 4096 bytes are rejected.
- Files are opened without following symlinks, must be regular files
  owned by the current user, and must grant nothing to group or
  other (Unix). Credential handling is Unix-only.
- Secrets never reach logs, error text, or diagnostics — stages, ids,
  errnos, and latencies only.

## Diagnostics and exit codes

- `mount` initializes structured diagnostics first: events to stderr
  plus `drive_dir/mount.log`, truncated per mount (one mount, one
  log — no rotation code). Init, export, member, and device log nothing to disk.
- `E2E_RUST_LOG` (honored by the Lima suite in `lima/run-alpha.sh`
  and the microVM gate in `nix/microvm/run-microvm.sh`)
  sets the mount's `RUST_LOG` for stuck-peer forensics, e.g.
  `E2E_RUST_LOG=wyrd_core=debug ./lima/run-alpha.sh --keep --step 6`.
- `--help` and `--version` print and exit successfully.
- Exit `0` on success; exit `2` on any failure, with the reason on
  stderr (`error: ...`). Usage errors (bad flags, missing options)
  are failures too, not help text. A transport teardown failure also
  fails the mount: a bulk close that times out exits as a bulk error,
  a serving shutdown failure as a serving error — after the
  mountpoint is already unmounted.
