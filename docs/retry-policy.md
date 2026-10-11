# Retry policy

Roadmap item 2 (`Retry policy: failure ordering, dial/transfer split,
route freshness`). All three items optimize correct behavior — the
fair-share floor bounds dead-dial cost, cooling is correct, no
freshness evidence exists — so none of them changes fetch
correctness. The demand contract they serve is property 8 in
`docs/fetch-on-open.md`; the implementation is `bulk.rs`'s candidate
walk in `wyrd-sync`.

## Status

1. **Dial/transfer split — implemented.** Each attempt runs two
   explicit phases: dial under its own allowance
   (`dial_allowance = min(30s dial bound, attempt budget)`), then
   size discovery plus streaming under the leftover
   (`transfer_allowance = attempt budget − dial elapsed`). Timeout
   instants and error classes are unchanged from the single shared
   deadline: a dial-phase expiry classifies exactly as a dial
   timeout did, a transfer-phase expiry exactly as the whole-attempt
   timeout did (`Deadline` under a subdivided share, `Transport` on
   a full share). What the split adds is measurement: every attempt
   records its phase outcome, dial latency, and bytes streamed
   before failure (see Metrics below).
2. **Freshness ordering — implemented.** The walk orders each
   pass's candidates from a per-provider outcome memory on the
   source: providers with a live failure mark sink behind unmarked
   ones, publication order stable within each tier, nobody dropped.
   Only completed observations train the memory — transport
   failures lay a mark, sliced-deadline expiries and oversize do
   not, fulfillment clears. Marks expire after 5 minutes (judgment:
   spans passes, recovers restarted peers without operator action).
   Rulings on the open questions: re-announcement clears nothing
   (an announcement attests addressing, never liveness — otherwise
   a dead route re-announced every pass would never sink);
   engine cooldowns are untouched (per-representation, above the
   walk; strike counting unchanged); no K-cap (dropping candidates
   would risk displacing a live alternate — sinking never skips).
   One honest interaction: the walk returns the last error and
   position sets the bound, so ordering moves which candidate's
   error class surfaces on total failure — in the evidence's
   direction (sunk dead tail reads fault, live head reads budget).
   Walk-only learning: single-route fetches neither lay nor clear
   marks.
3. **Cross-pass resume — deferred behind this note.** No
   `BulkSource` trait change, no partial-buffer ledger, no
   ranged-fetch implementation until the questions below are
   settled **and** the evidence threshold is met.

Non-goals (unchanged): multi-provider dead-first ordering through
intake (publication replaces per pass), single-route bypass
behavior (pinned by
`full_share_sliced_attempts_strike_like_master`).

## Resume feasibility (spike premises, not run code)

Resume looks buildable without a protocol fork, on premises read
from the pinned registry sources (`iroh-blobs =0.103.0`) during
the spike — none of them exercised by a ranged fetch in this
repository:

- The protocol source defines range constructors
  (`GetRequest::blob_ranges`, plus a builder with `root`/`offset`
  ranges) alongside range helpers for hash sequences and chunk
  probes. No high-level ranged getter exists beside `get_blob`,
  so a ranged stream would mirror `get_blob`'s internals.
- `iroh_blobs::get::fsm` is a public module (`low level API for
  getting data from a peer`), so that mirror needs no fork.
- Leaves arrive with offsets and the parents for requested ranges
  arrive inline per the Bao protocol, so a partial range should
  verify independently against the same root hash — and remaining
  ranges may come from a different provider. Size discovery
  already runs first, so missing ranges are computable.

The source reading establishes feasibility; only a prototype
fetch would establish it as run code. Worth is not established
either way: a partial-state implementation is the most invasive
of the three items (trait change, cross-call state, ledger
interaction, a second fake) for a pressure that has never been
observed — lists are short, no hanging tails on record.

## What the resume note must settle before implementation

- **Identity and integrity:** key partial state by the complete
  representation identity, not an ambiguous transport locator.
  Every resumed range verifies against the same root and size.
- **Bounded resource use:** a hard aggregate memory ceiling across
  concurrent partial blobs, eviction behavior, and cleanup after
  expiry or failure. The 64 MiB per-object fetch ceiling
  (`Limits::V0.max_object_bytes`) is not an aggregate bound.
- **Burn-ledger semantics:** distinguish lack of progress from
  partial progress. Repeated slices must not cool a provider as
  though every attempt made zero progress, but partial progress
  must not grant a stalled transfer unlimited immunity.
- **Expiry and classification:** preserve the `AttemptBound`
  distinction. Expired partial work stays deadline evidence —
  never misclassified as corruption or provider dishonesty.
- **Compatibility and fallback:** when to discard partial state
  and restart with a full-blob fetch (representation changes,
  invalid stored ranges).

## Evidence threshold

Reopen the resume decision if instrumentation shows repeated
large-blob transfers restarting from byte zero, persistent tail
stalls, or meaningful wasted bandwidth attributable to restarts.
Short provider lists and no observed hanging tails do not justify
the complexity pre-emptively.

## Metrics (the split's instrumentation)

`IrohBulkSource` keeps cumulative `BulkFetchStats`: attempts,
dial-phase timeouts, transfer-phase timeouts, fulfilled fetches
with their bytes, and **wasted bytes** — content bytes streamed in
attempts that then failed, the direct measure of restart waste
and the numerator for the resume threshold. The snapshot has no
production consumer yet: it is a test and diagnostics surface,
and the threshold reads the debug forensics below until a
diagnostics surface adopts it. Every attempt also
emits a forensics line (provider, hash, phase, dial latency,
streamed bytes, outcome) so per-representation repeats are
computable from logs without new retained state. `MemoryBulkSource`
needs no stats: its attempts are instant.
