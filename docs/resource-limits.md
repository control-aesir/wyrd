# Runtime resource limits

Normative bounds for live operation: which finite resources the daemon
budgets, what happens at each bound, and how exhaustion surfaces. The
protocol ingest ceilings (`Limits::V0`, bounding every committed
object) are not in scope here — they bound committed data, while this
doc bounds the live process holding and moving it.

All bounds live in one struct, [`ResourceBudgets`](../crates/wyrd-core/src/budgets.rs),
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

## Intake computational budgets

Byte ceilings alone do not bound CPU: a syntactically valid,
cryptographically valid, semantically invalid message sails through
cheap checks into expensive stages. The intake pipeline therefore
orders cheap rejection ahead of expensive verification, and memoizes
the one unbounded walk. Per-stage worst case for one hostile message:

| Stage | At most | Enforcement |
|---|---|---|
| Mailbox handover | 96 KiB ciphertext, 64 KiB opened bytes | `MAX_MAILBOX_CIPHERTEXT_LEN` / `MAX_MAILBOX_OPEN_BYTES` reject pre-ingest; unopenable envelopes discard with no fact |
| Control framing | 82-byte floor, then version / drive / epoch-key lookups | `SealedControl::decode` + `ControlInbox::ingest` reject before any crypto |
| Suppression redelivery | one hash over the sealed bytes, never an AEAD open | remembered verdicts apply before `open`; the id covers the sealed bytes so the verdict is stable across the open boundary |
| Announcement | two hash-map reads before one BIP-340 verify | membership lookup + epoch agreement precede `verify_announcement`; unseen transitions defer, mismatches suppress, verification still gates every commit |
| Transition | length + count gates before observation | `check_total_len` / `check_transition` (`Limits::V0`) precede `MembershipLog::observe`; signatures verify inside chain analysis |
| Chain traversal | one full analysis per observed-set version per batch, regardless of verdict reads | `MembershipLog` memoizes the analysis; `observe` is the only mutation and invalidates. Verdict reads borrow the cached maps (no per-lookup copies). No depth cap by design (10k-deep chains are pinned conformance) — the bound is analyses-per-batch, not depth |
| Capability | one ECDH+AEAD unwrap of envelope-bounded bytes, then one memoized authorize | `WrappedCapability::unwrap` before `AuthorizedCapability::authorize`; unknown transitions defer into the 1024-bound pending shed, terminal history suppresses |
| Rotation delivery | device check + transition decode + limits + epoch agreement before the unwrap | structural gates precede `WrappedCapability::unwrap`; the transition↔capability binding check stays after it (the binding lives inside the wrap) |
| Manifest / object fan-out | none on intake, by construction | intake commits only transition / announcement / capability / control-message facts and never opens manifests, trees, or chunks; expansion is pull-based post-intake under the fetch byte ceiling and manifest count gates |
| Commit rate | no time-based cap | structural: invalid commits 0 facts, replay commits 0 facts, over-limit deferrals shed with the relay retaining. Insider commit-rate bounding is the separate fact-log spam issue, not this table |

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
  by the backend's request probe.
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
bound the durable and in-memory dedupe state. Proven by the
`mailbox::tests_backpressure` suite.
