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
wyrd pin --identity-file <path> --passphrase-file <path> <drive_dir> <path>
wyrd unpin --identity-file <path> --passphrase-file <path> <drive_dir> <path>
wyrd evict --identity-file <path> --passphrase-file <path> <drive_dir> <path>
wyrd cache --identity-file <path> --passphrase-file <path> <drive_dir> (status [path] | policy)
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
  Removal bounds acquisition, not knowledge: a removed device keeps
  its local plaintext, and can keep fetching any content whose
  transport root it learned before removal, from any serving member
  that still answers. It learns no new roots.
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
    = connects when given a relay (a relay-less run is refused
      without --offline)
    = may mutate durable state
    = reports network liveness plus mailbox intake posture (a
      relay-closed subscription degrades the verdict even when every
      relay is connected; a degraded mailbox fails the run as
      unverified, whatever the local state — quiet observed through
      a blind intake is never reported as converged, including a
      blind stretch that healed mid-run: the lifetime
      recovery-attempt counters prove an episode ran, so the quiet
      verdict may predate the healing. Episodes only fire after
      first attachment, so a slow cold start never counts.)
    = either converges or explicitly reports incomplete
```

- `status`: pending outbox obligations with their queued,
  delivered, and pending split (announcements per snapshot,
  transitions per transition id, capabilities per epoch), the known
  membership tip against held epoch secrets (knowledge is not
  possession), live heads with classification counts over every DAG
  head, and mailbox posture. A `reconciliation` row reports control-plane
  recovery progress from committed facts only: statements received,
  plus transitions and capabilities retired by reconciliation. The row
  names classes and counts, never identities — the outstanding gap
  itself is volatile (answering resets on restart), so it lives on
  `now` as two gauges — never evaluated, plus evaluated-but-stuck —
  not here. Read-only against durable state only:
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
   lock error while a mount holds it. Four projections join the
   read: peers as opaque handles (`peer-1`, `peer-2`, stable for the
   rendering, derived deterministically so the same state renders
   the same handles across restarts — never a persisted identity
   namespace), the durable queue depth (outstanding outbox pairs
   plus reconciliation gaps, from committed facts only — not the
   in-memory queue; staged carries count in the outbox total, on no
   peer line, and render on their own line when nonzero),
   convergence from durable facts (converged, or what still
   diverges), and materialization as counts (explicit
   cached/pinned policies plus locally held objects). Connectivity
   reads `not observed`: status never connects, so it says the
   omission out loud instead of letting silence read as healthy.
- `now`: runs the mount's sync machinery (drain, deliver,
  announce, fetch through `sync_once`) with the mount's live
  budgets and no FUSE session: vaults and NAS replicas converge
  without mounting. Stops on the first quiet pass and prints pass
  and intake/fetch totals with the obligations still pending.
  The intake clause splits deferred holds by cause (`unseen`,
  `status-blocked`, `shed`), the fetch clause counts sends, and a
  `write path` section reports the local durability load beside
  the sync load: mutation-seam snapshots with their per-minute
  rate, the per-source share (mkdir, create-file, commit-file,
  append-file, unlink, rmdir, rename, set-attrs, fold — variant
  classes, never paths), and admission-to-commit latency (mean and
  max). Write-path statistics are process-local and cover only
  mutations submitted to this run's in-memory mutation queue:
  mutation-seam commits only (direct engine authoring bypasses the
  traced seam), and headless commands such as `sync now` do not
  submit mutations, so their write-path statistics are zero.
  The mailbox line names saturation recoveries beside closed
  subscriptions and recovery attempts.
  At most 32 passes: a peer that keeps intake non-idle forever
  (which a mount absorbs by running forever) trips the cap, which
  reports `stopped: pass limit (32) reached; sync may be
   incomplete` and exits non-zero — a capped run is never reported
   as converged. Refusal burns the cap the same way: a relay
   configuration that accepts nothing keeps the outbox pending
   forever, so the run never reaches quiet — the pending count names
   the stuck obligations. A run that stops with known-but-unfetchable heads
   exits zero with a healthy mailbox: the outbox is empty and there is
   nothing local left to do, so a non-zero exit would only invite
   pointless retries — automate on the `unfetchable heads` count, not
   the exit status, when that distinction matters. With a degraded
   mailbox the same stop exits non-zero as unverified instead: the
   empty outbox was observed through a blind intake, so "nothing
   left to do" is unproven — including an intake that went blind
   and recovered, which reads degraded with its attempt count, not
   live. Stalled is a verdict about observed emptiness, not about
   reachability — an unreachable relay never earns the quiet exit.
  Quiet is never trusted on first sight: relay delivery races the
  first drain, so a quiet verdict parks a short settle window
  (arrival short-circuits it) and confirms with a second pass.
  A quiet outbox does not imply a closed control plane: the run
  reports a `reconciliation` line with two gauges — received
  statements it never evaluated, plus evaluated-but-stuck ones
  whose requester is still owed ("asked, nothing delivered": the
  sender-side UnknownEpoch skip, which marks answered yet records
  a stall). An open gap fails the run even when the outbox is
  quiet — a peer asked and this device could not prove its state,
  so automation keying on exit status sees it. Zero
  prints too: the converged case is grepable, not omitted.
  A head whose closure is not local is a remote
   condition, not local work: after one grace pass it stops the run
   as quiet with an explicit `N unfetchable heads` count instead of
   burning the cap. Zero-progress passes park the settle window too,
   so dead churn waits on the relay instead of spinning. A
   `senders observed` section names the distinct senders whose
   envelopes the run processed, by full `DeviceId`: this process
   connected and the operator holds the keys, so the run surface may
   say who it heard. A sender is any key that mailed us, member or
   not — this is a sender list, never a membership roster. The two
   surfaces answer different questions (who mailed us vs who we owe
   and who authored our heads) and never share a representation:
   the durable surface reports obligation peers as opaque handles.
- `--relay <url>` (repeatable, shared parsing with `mount`): with
   none given, `now` refuses with a usage error unless `--offline`
   is passed — a relay-less run exits 0 with an idle intake, which
   automation keying on exit status cannot distinguish from a
   converged sync. With `--offline`, intake stays idle: `now`
   discharges local obligations and fetches nothing new. The mailbox
   line reads `idle (no --relay given)` there — an explicitly offline
   run claims neither liveness nor degradation — and the completion
   line reads `completed: quiet (offline run: local obligations
   only)`, so the last line states the scope it converged. `--offline`
   cannot be combined with `--relay`.

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

### `pin` / `unpin` / `evict` / `cache` — local materialization policy

What this device intends to retain, declared per subtree and stored
durably in this device's log. Policy facts are never published,
never authorize anything, and never alter a snapshot — pinning a
subtree changes nothing any other device can observe.

Two independent columns, never merged:

```text
POLICY       what this device intends to retain (PINNED / REMOTE_ONLY)
LOCAL        what bytes happen to exist (PRESENT / ABSENT)
```

The store is append-only with no GC, so `REMOTE_ONLY` + `PRESENT`
is ordinary: eviction releases intent, never deletes bytes. A file
reads with a retention promise only at `PINNED` + `PRESENT` over
every chunk. The fetch loop's arrival marking (`Cached`) carries no
retention promise and reports as `REMOTE_ONLY` policy.

- `pin <path>`: promise every byte under `path`. Offline,
  idempotent, never fetches — the next sync or mount fetches what
  the policy now requires. Policy is per content identity, so a
  chunk shared with files outside the subtree carries the promise
  there too.
- `unpin <path>`: release the promise (pinned returns to cacheable
  policy). Never deletes bytes, never refuses. Promises are per
  content identity, not per path: unpinning a subtree releases
  shared chunks other pinned paths also relied on.
- `evict <path>`: return unpinned content to `REMOTE_ONLY` policy.
  Refuses the whole subtree while any of it is pinned (unpin
  first) — a partial evict would let overlapping paths silently
  narrow a promise. Intent only: no bytes deleted, files that stay
  fully local keep reading.
- `cache status [path]`: one row per reachable file with its
  policy/presence pair, plus quadrant totals. Reachable content
  only — the object store as a whole is never scanned.
- `cache policy`: device totals over reachable content plus the
  effective retention and fetch budgets. Facts are per identity,
  not per path, so pinned paths are not listed. Below the budgets,
  a `retention accounting (bytes):` block reports three resident
  dimensions measured at report time (three walks, never cached):
  `retained content` (the object store — the quota-enforced quantity),
  `fact log` and `sync vault` (resident but unenforced — auxiliary
  growth), each labelled, plus an observational total. With no quota
  configured the block ends in an explicitly non-authoritative
  advisory ceiling ("no lower than current retention"); a quota is
  an operator-selected refusal boundary, never an implicit default. The
  report names the local quota only: the refusal ceiling and the
  receive-side ceiling required by `docs/retention-constraints.md:147-149`
  have no value to report until the receive-path admission gate lands.

Conflicted paths refuse every mutating policy command: resolve
first, or address one version through the existing `path@N`
grammar. `cache status` instead renders them as `CONFLICT` rows —
a read-only report survives the ordinary multi-head state. One
invocation walks one generation — heads install once up front, so
a concurrent local write cannot mix generations into it. Policy
commands need the drive un-mounted regardless: the durable store
takes an exclusive lock, so a policy command against a mounted
drive fails closed with the lock error. And pinning promises
retention without fetching: a pinned-but-never-fetched subtree
still fails closed offline (export names the unheld bytes) until
a sync or mount lands the bytes.

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
- Drive custody files are created owner-only on Unix regardless of
  umask: `store-key.wrap`, `keystore`, `pairing.secret`, and `LOCK` at
  `0o600`, the drive directory leaf and `commits/` at no wider than
  `0o700`, `DRIVE` at no wider than `0o644`. Modes are never loosened:
  a replaced custody file takes the hardened mode through the rename.
  Only the leaf directory this call creates is restricted, except that
  establishing fresh drive state restricts the directory it is given;
  missing parents above the leaf keep the operator's modes. Subdirectories
  created later for operational state (`escrow/`, `vault/`, `serve/`)
  stay umask-derived — contained by the `0o700` parent on fresh drives
  — and are a separate hardening issue. Pre-existing files and
  established drives are otherwise untouched — inspect a pre-fix drive
  with `stat` (e.g. `stat -c '%a %n'` on Linux, `stat -f '%Lp %N'` on
  macOS) and repair by hand. Non-Unix platforms get no mode guarantee.

## Diagnostics and exit codes

- `mount` initializes structured diagnostics first: events to stderr
  plus `drive_dir/mount.log`, truncated per mount (one mount, one
  log — no rotation code). Init, export, member, and device log nothing to disk.
  Every dispatch line carries the opcode, its reply errno, its
  latency, and the mutation-queue backlog observed at dispatch
  entry — queue pressure per dispatch, no metrics pipeline.
- Trust position of these surfaces: `sync status`, `sync now`, and
  `mount.log` speak for a client holding its own keys, never for a
  vault. No vault-position diagnostics surface exists: the matrix
  and enforcement that generalize this statement land separately,
  sequenced after `wyrd vault`, because a boundary needs a vault
  process to be meaningful and none exists. What these surfaces
  print is counts, latencies, class breakdowns,
  and pressure against the bounds in `resource-limits.md`. What
  they never print is ContentIds, filesystem paths, file bytes,
  or secrets — the observation half of the privacy boundary.
  Snapshot and membership transition ids do appear on `sync status`:
  the tip line names the applied head, per-item lines name the owed
  obligation, live-head lines name the held heads — that is their job
  as merge identities, and no DeviceId appears beside them there.
  The `reconciliation` row goes further and names no identities at
  all: three counts (statements received, transitions and capabilities
  retired), so a future field cannot smuggle an id onto the surface.
  DeviceIds never reach the durable `sync status` surface or the
  log; `sync now` alone names the senders its intake actually
  heard, because that process connected and the operator holds the
  keys. (`member list`, `member log`, and `snapshot list` are
  separate read surfaces with their own contract — they name
  members and authors explicitly, and this paragraph does not cover
  them.)
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
