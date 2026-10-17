# Retry policy

Roadmap item 2 (`Retry policy: failure ordering, dial/transfer split,
route freshness`). All three items optimize correct behavior — the
fair-share floor bounds dead-dial cost, cooling is correct, no
freshness evidence exists — so none of them changes fetch
correctness. The demand contract they serve is property 8 in
`docs/fetch-on-open.md`; the implementation is `bulk/iroh.rs`'s candidate
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
   attempt's candidates from a per-provider outcome memory on the
   source: providers with a live failure mark sink behind unmarked
   ones, publication order stable within each tier, nobody dropped.
   Only dial-phase failures train the memory — transport failures
   from the dial lay a mark, sliced-deadline expiries do not, and
   transfer-phase failures (including a live member's legitimate
   "not found" for one representation) never sink the provider for
   others it serves. Fulfillment clears. Marks expire after 5
   minutes (judgment: spans passes, recovers restarted peers
   without operator action).
   Rulings on the open questions: re-announcement clears nothing
   (an announcement attests addressing, never liveness — otherwise
   a dead route re-announced every pass would never sink);
   engine cooldowns are untouched (per-representation, above the
   walk; strike counting unchanged). One honest interaction: the walk returns the last error and
   position sets the bound, so ordering moves which candidate's
   error class surfaces on total failure — in the evidence's
   direction (sunk dead tail reads fault, live head reads budget).
   Learning happens in `fetch`, so any attempt trains the memory —
   walk or single-route: dial reachability is provider-level,
   independent of the representation asked for, and fulfillment
   clears from either path.
3. **Walk bound — implemented (`FETCH_WALK_CAP = 3`).** Each pass
   attempts at most the first three freshness-ordered candidates.
   This supersedes the earlier "no K-cap" ruling: the displacement
   worry is answered by paging, not by attempting everything.
   Fault-failing heads mark and sink, so consecutive passes page
   through a failing tail; un-attempted candidates record nothing
   (no strike, no burn) and retry next pass by republication. The
   fair division counts only the capped reach, so no share is
   reserved for candidates the pass will not ask. Paging covers
   dial-phase hangs too — the K-th attempted head always holds the
   full remaining share, so its dial expiry classifies as fault
   evidence (like an uncapped walk's last candidate) and marks,
   sinking one hung head per pass. The accepted limit:
   transfer-phase hangs never mark, so K or more persistently
   stalled transfers pin a live tail behind them until they fault,
   clear, or the representation's strike/burn cooldowns trip (the
   pinned passes still strike-cool through the last attempted
   expiry). Revisit when lists grow past three live routes or the
   forensics show pinned tails.
4. **Cross-pass resume — spiked, no-go for implementation.**
   The spike ran against the pinned sources (`iroh-blobs
   =0.103.0`) and answered the four design questions below. All
   answers are source-verified premises, none exercised by run
   code in this repository. Verdict: do not implement — the
   mechanism is buildable but the pressure it relieves has never
   been observed, and the cheapest correct form still touches the
   burn ledger's duty-cycle bound. The evidence threshold below
   reopens the decision; no follow-up issue is filed (this note
   is the tracker).

Non-goals (unchanged): multi-provider dead-first ordering through
intake (publication replaces per pass), single-route bypass
behavior (pinned by
`full_share_sliced_attempts_strike_like_master`).

## Resume spike: the four questions answered

**1. Range-request shape.** No protocol fork. `GetRequest::blob_ranges(hash,
ranges)` (`protocol.rs`) builds a range request over
`ChunkRanges`; `get::fsm` is a public module whose `start`
accepts any `GetRequest`, so a ranged fetch mirrors
`get_blob_impl`'s drive loop (`AtInitial → AtConnected →
AtStartRoot → AtBlobHeader → AtBlobContent → AtEndBlob →
AtClosing`) with a range request in place of `GetRequest::blob`.
Ranged requests are exercised by iroh-blobs' own helpers
(`random_hash_seq_ranges`, chunk probes), so providers serve
arbitrary ranges. No high-level ranged getter exists beside
`get_blob` — the mirror is handwritten, not configured.

**2. Partial-state ownership and lifetime.** Key by the complete
representation identity — the transport root hash plus the
verified size from size discovery (which already runs first),
never a provider or address. Home: an in-memory map on
`IrohBulkSource` beside `provider_memory` and `stats` —
cross-pass state, not cross-restart (a restart loses partial
work, correctly: it is an optimization, never durability). No
`BulkSource` trait change: `fetch` consults the cache, requests
only the missing chunk ranges, stitches, and returns complete
bytes only when whole — the boundary contract is unchanged.
Bounded use: a hard aggregate ceiling on buffered partial bytes
(the 64 MiB per-object fetch ceiling is not an aggregate
bound), oldest-first eviction, entries dropped on fulfillment,
on size rediscovery disagreeing (representation changed —
discard, never stitch across identities), and on representation
cooldown. Resume granularity is whole verified chunks: a stream
cut mid-chunk loses that chunk's tail (bao verifies per
chunk), so only chunk-aligned prefixes are retainable and the
progress probe's byte count overstates the resumable prefix.

**3. Stream stitching and final verification.** Ranged responses
carry their own bao proofs (parents inline), so every range
verifies independently against the same root hash through the
same fsm decoder — no new trust, and remaining ranges may come
from a different provider than the prefix (ranges are
hash-keyed, provider-independent). Leaves arrive offset-tagged
(`Leaf { offset, data }`), so stitching is positional into the
stored prefix; completion is coverage of `[0, size)`, and the
assembled bytes return only then — the engine still never sees
unverified bytes. Testing needs a second fake (a scripted
range-serving source); the memory source's instant attempts
have nothing to resume.

**4. Pass-budget interaction.** The `AttemptBound` classification
is unchanged: an expired ranged attempt is `Deadline` under a
subdivided share and `Transport` on a full share by the same
rule — expiry class is about budget, never about progress. The
hard question is the burn ledger: burns accumulate per sliced
expiry today, so a large blob making steady progress across
passes would still cool mid-transfer and resume would be
pointless for exactly the transfers it targets. Burns must
become progress-aware — a progress-making pass resets or
discounts the burn count — with a progress floor (whole chunks
per pass, not bytes) so a drip-stall cannot hold a
representation warm forever. That floor is the one judgment a
follow-up implementation must set; everything else above is
mechanism. Cooling stays progress-blind in the meantime, which
is correct for restart-from-zero transfers.

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
