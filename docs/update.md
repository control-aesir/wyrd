# `wyrd update` sequence and transaction contract

**Normative** for the `wyrd update` implementation (issue 29). Decides
OD-U2 and OD-U3 as one transaction per ruling: rollback, lifecycle,
and supervisor contract are specified together, not in three places.

Decisions: U1=B (local archive), U2=C (advisory preflight plus
authoritative post-swap check), U3=B (hand back; foreground
restart-and-return is an explicit mode), U4=A (verified /
incompatible / unverified, gaps named).

## The one deviation, stated first

The release review's sequence has `wyrd update` signal the daemon to
quiesce. This command does not signal, kill, or wait on any process —
in any mode. Three reasons, in order:

1. There is no pid to signal. The vault writes no pid file, and the
   only observable fact about the lock holder is `StoreLocked`.
2. Any kill path races the supervisor. Under `Restart=always` the
   supervisor restarts the binary at its path mid-swap, and the
   restarted process is whichever bytes won the race — closing that
   race needs supervisor awareness (inhibit, stop, start), which is
   `36-vault-packaging`'s job and would make the update's
   correctness depend on incidental timing (forbidden by condition
   4 below).
3. Quiesce/flush/unmount already exists as tested behavior on the
   vault's own SIGINT/SIGTERM path (`main.rs:949` arms the signals;
   SIGTERM after readiness exits 0 per `main.rs:3231`, pinned by
   `crates/wyrd-cli/tests/vault_process.rs`). Re-implementing that
   teardown inside the updater duplicates it badly.

So: **quiescence is a precondition update checks, never a state
update produces.** Who stops the old process is answered per mode in
§2; how update knows it stopped is always the same authority — the
store lock (§3).

## 1. Modes

Two explicit modes, never guessed (U3):

- **Supervised (default).** The process owner — operator,
  `systemctl stop`, `launchd`, Ctrl-C on a foreground vault —
  stops the old process first. Update refuses a held lock naming
  the condition (`stop the service first`), then swaps, verifies,
  and exits: 0 with the new binary in place and verified, nonzero
  with the old binary restored. The owner restarts whichever
  binary is in place; update prints which one it left.
- **`--restart` (foreground).** Same precondition (the old vault
  must already be stopped — Ctrl-C first), but after a committed
  swap update starts the new `wyrd vault` as its own child and
  waits on it, forwarding SIGINT/SIGTERM and propagating its exit
  status. On a failed verification it restores the old binary and,
  under `--restart`, starts the *old* vault instead — rollback
  with continuity. Update is the supervisor for exactly this run;
  nothing is inferred about systemd, launchd, or any other owner.

Relay flags ride `--restart` only (forwarded to the vault child);
without it they are refused as meaningless.

## 2. Ownership (condition 4)

| Act | Supervised | `--restart` |
| --- | --- | --- |
| Stop the old process | process owner (update refuses a held lock) | operator Ctrl-C first (same refusal) |
| Stage, swap, verify | update | update |
| Restore on failure | update, before handing back | update, before starting the old child |
| Start the replacement | process owner (`systemctl start`, …) | update spawns the new vault child |
| Restart policy | supervisor's own | update forwards signals, propagates status |

Update never holds the store lock itself outside the verification
child (§4), and never competes with an owner for it: the lock probe
(§3) and the verification open are both brief, and any `StoreLocked`
between them means the world changed under the transaction — which
is a rollback, not a retry.

## 3. Quiescence proof (advisory) vs authority

- **Probe (advisory, fail-fast).** Before staging anything, update
  asks `wyrd-sync` for a lock-only probe of `<drive>/LOCK`:
  create-owner-only-if-missing, `try_lock`, release immediately.
  Held means refuse with `stop the service first` — a usage
  error, with nothing staged and nothing stopped. The probe reads
  no state and writes nothing but the lock file's creation; in
  particular it never runs `DurableStore::open`, which mints keys
  and writes DRIVE on fresh directories. The probe lives in
  `wyrd-sync` beside the lock it interprets, not in the CLI.
- **Authority (the lock itself).** The verification child opens the
  store for real. If the old process came back between probe and
  verify, the open fails `StoreLocked` and the transaction rolls
  back. The probe exists so the common case fails fast with a
  clear message; the lock exists so the race fails safe.

## 4. Phases and the recovery protocol (conditions 1–3)

All updater state sits beside the target executable
(`std::env::current_exe`), never in the drive: the drive may be
unreadable mid-transaction, while the executable's directory is
always writable by whoever may replace the binary. Same directory
means same filesystem, so every swap step is one atomic rename.

- `<exe>.next` — the staged new binary (extracted from the
  archive, executable bit ensured).
- `<exe>.prev` — the old binary, kept until commit.
- `<exe>.update-state` — JSON transaction record
  `{version: 1, drive, archive: {name, version, blake3}, phase}`.

Phases, in order:

1. **Resolve.** Validate the archive (name, regularity, digest);
   refuse ambiguities before anything is disturbed. Pure; no
   state file yet.
2. **Require quiescence.** Lock probe (§3); held means stop here.
3. **Stage.** Extract `*/bin/wyrd` from the archive into a
   same-directory staging dir, move to `<exe>.next`, write state
   `{phase: staged}`. Crash here: old binary untouched; next
   update removes `.next` and resumes.
4. **Preflight (U2-A, advisory).** Run the staged binary's
   lock-free self-report and compare against this binary's own:
   if the new build's minimum envelope version exceeds what this
   build writes, refuse before the swap. Advisory means exactly
   this: it catches binary-level impossibilities, never
   per-drive truth.
5. **Swap.** Rename `<exe>` to `<exe>.prev`, `<exe>.next` to
   `<exe>` — two atomic renames, state `{phase: swapped}` between
   them. Crash between the renames: reality is one side or the
   other (rename is atomic); the state record plus a digest
   comparison of what's in place converges to either
   complete-the-swap or restore-and-`staged`. No third outcome.
6. **Verify (U2-B/C, authoritative).** Spawn `<exe>
   __update_verify <drive>` (hidden internal subcommand, §5) and
   wait with a timeout. Exit 0 with a `verified` report commits;
   anything else — nonzero, timeout, signal, or a report that is
   not verified — restores `<exe>.prev` over `<exe>` and exits
   nonzero. The old binary is never deleted before this verdict.
7. **Commit / hand back.** State `{phase: committed}`, remove
   `<exe>.prev` and the state file — only now is rollback
   impossible. Supervised: print the binary in place and exit 0.
   `--restart`: spawn it as the vault child (§1).

Recovery rule: **every `wyrd update` invocation first reads
`<exe>.update-state`.** A leftover record means the previous run
died mid-transaction; the invocation converges reality to a clean
state (complete or roll back per §5's table) before starting
anything new. There is no separate recovery command and no
recovery migration (upgrade invariant 9): the protocol is
complete-the-rename or undo-the-rename, decided by digests, and a
drive that never saw a verified new binary is byte-identical to
before.

## 5. Verification boundary (condition 2)

`__update_verify` is internal and unstable by design (double-underscore):
it is the new binary checking the actual store, not an operator
tool. It MUST: open the store (taking the lock briefly — this is
the authority from §3), replay durable facts through the new
build's readers, exercise replay and the applicable upgrade
invariants for real — a successful open alone is NOT a pass —
print the U4 report lines, and exit 0 only on `verified`. It MUST
NOT: announce, serve, emit transitions (upgrade invariant 6 is
checked as membership-log byte-identity), hold the lock beyond the
check, or write derived state into the store's derived locations
(scratch paths only: a failed verification must leave no
new-version derived files for the restored old binary to trip
on). Unknown envelopes refuse loudly with their names (invariant
10); the two named gaps (fact-payload replay, version matrix)
ride every report as unverified, never omitted.

### Invariant-to-check mapping (step 3)

Each `update check:` line ties to exactly one upgrade-contract
invariant; anything else the report prints is data (versions),
never a claim:

| Invariant | Check |
| --- | --- |
| 1 — immutable data stays readable | `N commits replay` (history loads) plus `M live heads authorize` (snapshots verify). Object *payload* bytes are the one residual: no public store-enumeration API exists, and the CLI must not reconstruct the object layout beside the store — so payload framing is not sampled here. Payload bytes are immutable CAS served hash-verified; a framing break there fails at serve time, loudly, and never corrupts. |
| 2 — explicit versions | Any explicitly-versioned format that fails to decode is `incompatible (invariant 2: <error>)`. The payload clause is the named fact-payload-replay gap. |
| 3 — read window | The replay is this drive's own history under the new readers. |
| 4 — derived rebuilds | The byte-identity proof: derived state lives outside the snapshotted files, so anything load-bearing the verify wrote would show as a difference. |
| 5 — capability negotiation | Named gap, never claimed. |
| 6 — no transition emitted | Keystore plus observed membership set byte-identical. |
| 7 — additive crypto | Epoch keys restored inside the open; the open fails closed otherwise. |
| 8 — permanent history | Commit set and CURRENT unchanged. |
| 9 — interrupted reopen | The transaction protocol (§4), covered by its own failure-injection tests — not by the verify child. |
| 10 — fail closed | Unknown control versions/kinds are `incompatible (invariant 10: unknown control version 0x..)` with the byte named. |

A `verified` report therefore claims exactly: this build opens
the store, replays its history, authorizes its heads, restores
its epochs, and leaves every durable byte identical — with the
two named gaps plus the payload-bytes residual outside the
claim. Anything narrower is not verified; anything broader is
not this report.

## 6. Output and exit contract (condition 5, U3, U4)

- Every line is a stable `update <key>: <value>` pair: one format,
  human- and machine-readable. Compatibility is `verified (N
  checks)` with one `update check:` line per check,
  `incompatible (invariant <n>: <detail>)`, or `unverified
  (<gap>; <gap>)` — never an unqualified green.
- Exit 0 means exactly: the new binary is in place, verified, and
  (under `--restart`) running as the supervised child. Exit 2
  means anything else — with the old binary restored whenever
  restoration was possible, and the message saying which binary
  is in place and how to resume. A failed restoration is the one
  catastrophic case: same exit code (the binary-wide convention
  is 2 for all errors), but the message names manual recovery
  explicitly instead of implying rollback happened.
- Under `--restart`, the child's exit status propagates once the
  child exits; signals forward so Ctrl-C behaves like a bare
  vault run.
