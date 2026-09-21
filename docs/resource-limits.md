# Runtime resource limits

Normative bounds for live operation: which finite resources the daemon
budgets, what happens at each bound, and how exhaustion surfaces. The
protocol ingest ceilings (`Limits::V0`, bounding every committed
object) are not in scope here — they bound committed data, while this
doc bounds the live process holding and moving it.

All bounds live in one struct, [`ResourceBudgets`](../crates/wyrd-daemon/src/budgets.rs),
threaded from `LiveConfig` into the loop, the registries, and the
backend at composition time. Defaults are the historical hardcoded
bounds — with two intentional new ones: the per-pass admission cap
(admission was previously uncapped per pass) and the open-handle cap
(the table previously relied on the kernel descriptor limit alone).
4096 handles is far above plausible interactive use (tens of open
descriptors) while bounding pinned-capture memory, so it does not
regress supported workloads. `ResourceBudgets::default()` is the
pinned contract for the legacy defaults. Tuning is library-level:
the `wyrd` binary takes no flags for these today and runs defaults.

## Bounds

| Boundary | Bound (default) | Past it |
|---|---|---|
| Want registry identities (pending + admitted) | `max_pending_wants` (4096) | registration fails; `EIO` at the POSIX boundary, never a silent drop |
| Want admission per sync pass | `max_admit_per_pass` (1024) | remainder stays pending for the next pass — paced, never dropped |
| Mutation queue (admitted-but-incomplete) | `max_pending_mutations` (4096) | submission fails `Saturated`; `EAGAIN` |
| Write buffer per dirty handle | `write_per_handle_bytes` (64 MiB) | reservation refused; `ENOSPC`, handle unchanged |
| Write buffers aggregate | `write_aggregate_bytes` (256 MiB) | reservation refused; `ENOSPC` |
| Dirty (buffered) handles | `write_dirty_handles` (64) | new dirty handle refused; `ENOSPC` |
| Open file handles (read + write) | `max_open_handles` (4096) | open refused; `EMFILE` |
| Mailbox notification channel | 1024 events (const) | backpressure stalls the relay stream; the relay retains everything |
| Mailbox held handovers | 1024 unacked (const) | `recv` stops pulling; held mail rotates so the engine drains free |
| Engine intake held messages | `MAX_PENDING_MESSAGES` 1024 (const) | over-limit deferrals shed without consuming; relay redelivers |

The mailbox and engine-intake bounds stay constants: they are
protocol-adjacent, already bounded and backpressure-tested, and not
operational tuning. The daemon-side bounds above are the configurable
ones.

## Bytes in flight

Fetch execution is single-threaded per pass, so "bytes in flight" is
the admitted-but-unlanded set: at most `max_admit_per_pass`
identities, each at most `Limits::V0.max_object_bytes` (the ingest
ceiling rejects anything larger before it lands). The admission count
is therefore the byte bound's coarse handle:

> bytes per pass <= `max_admit_per_pass` x `Limits::V0.max_object_bytes`

There is no independent byte knob: the ingest ceiling already caps
the per-object term, and capping admissions caps the sum.

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
retry next pass. The run loop's backoff and consecutive-error cap
govern the aborted pass like any other engine failure; the supervisor
restarts the process and durable state picks up cleanly.

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
  by the backend's request probe.
- `LiveError::Engine(EngineError::Store(_))`: the pass-failure
  form of a fatal disk condition, subject to the loop's backoff
  and error cap like any engine failure.

## Mailbox saturation

Recorded here because the acceptance criterion names it: saturation
cannot silently lose control-plane work. At saturation `recv` stops
pulling from the notification channel (backpressure, not loss) and
held mail rotates so the engine drains room free; nothing is ever
consumed-and-dropped, because the live stream has no cursor and a
dropped event would wait for a resubscribe that may never come. The
bounded seen-id log (65,536 acks) and poison cache (4096 entries)
bound the durable and in-memory dedupe state. Proven by the
`live_mailbox::tests_backpressure` suite.
