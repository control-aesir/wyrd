# Sync and Peers

How Wyrd moves objects and snapshots between devices. `wyrd-sync`
implements the protocol/core boundaries; the runtime wiring that turns
them into a full distributed system is still in progress.

The identity model is defined in `object-model.md` (two identities: Content
ID / Storage ID). This doc describes how peers exchange them.

## Transport

- iroh endpoint with relay/DNS discovery and NAT traversal
- Pairing via tickets (one peer generates, the other imports)
- The iroh version set (iroh 1.1.0 / iroh-blobs 0.103.0 fs-store)
  is validated as a set and changes as a set

## Runtime sync boundary

The runtime work between the protocol primitives and the
filesystem surface — status each, since this list used to read as
all-remaining:

- persistent local state for membership, snapshots, manifests, materialization,
  capabilities, and pending work — landed (durable fact log, replay,
  restart reconciliation under test; `ROADMAP.md` Phase 1)
- bulk object transport and backpressure — mechanism landed
  (pass-budget fair-share, `fetch-on-open.md` property 8) and
  loopback-tested; measured pressure on a live network stays open
  (`ROADMAP.md` Phase 1, not a v0.2 blocker)
- crash recovery and restart reconciliation — landed, including
  torn-commit recovery (`ROADMAP.md`: crash recovery is shipped)
- read-only then read/write FUSE integration — landed; the mount
  serves read-write by default (`ROADMAP.md` Phase 2)

The control plane is wired both ways: intake drains the relay mailbox
into the engine every pass, and the same pass publishes undischarged
announcement, transition, and capability obligations back out
(`LiveNode::publish`, over the durable outbox the authoring paths
queue).

## Control-plane transport (Nostr mailbox)

The control-plane message set (`wyrd-sync/src/control/`) is transport-agnostic
bytes; `wyrd-sync/src/transport/` wraps it for the Nostr mailbox:

- **Mailbox seal**: every `SealedControl`/`SealedBootstrap` envelope travels
  inside an outer NIP-44 seal between the two devices' Nostr identity keys —
  two independent seals, the inner one authenticity (`trust.md`), the outer
  one relay confidentiality. Recipient discovery addresses the recipient's
  `DeviceId` directly (`trust.md` T16); this is the same traffic-analysis
  exposure as any two-party encrypted messaging, already accepted as
  best-effort.
- **`Mailbox` trait**: the send/receive boundary a relay client implements.
  Synchronous by design. The concrete relay pool lives one layer up,
  in `wyrd-core/src/mailbox/` — not in `wyrd-sync`, which owns only
  the transport-agnostic message set and this trait boundary. The
  pool is `LiveMailbox`: NIP-59 kind-1059 gift wraps over a durable
  seen-event-id dedupe log, one stable filter and subscription for
  the mailbox lifetime, CLOSE+REQ resubscribe transactions,
  capped-backoff drainer recovery with relay-health polling, and the
  event kind/tag conventions (rumor kind 9501, recipient `#p` tag,
  gift-wrap framing). It lives in `wyrd-core` because it composes
  node concerns — identity secrets, the signer boundary, relay
  supervision — while `wyrd-sync` stays composable protocol:
  anything implementing `Mailbox` (a test fake, a relay pool, a
  future mixnet drop) drives the same engine.
- **Test evidence, four legs**: a hermetic in-process NIP-01 relay
  (`MiniRelay`, real `EVENT`/`REQ`/`EOSE`/`CLOSE` over websockets,
  no live network); the heterogeneous cross-implementation episode
  beside it (`tests_crossimpl`: the fake plus rust-nostr's real
  in-process relay, in the default gate); the real-iroh but
  relay-disabled serving path for the bulk plane; and two opt-in
  tests against actual public relays (`mailbox::tests_interop`).
  Those two are `#[ignore]`d and
  excluded from every CI profile by rule (`.config/nextest.toml`:
  the ignore attribute is reserved for tests needing external
  resources, which must never run in CI) — the honest framing of
  current evidence is proven-against-public-relays by hand, not by
  gate.
- **Delivery contract — relay-accepted is the maximum v0.2
  guarantee**: `Mailbox::send` reports per-relay acceptance
  (`SendReport.accepted`), and the outbox commits a `Delivered`
  fact only when at least one relay accepted the write. A send no
  relay accepts leaves the obligation pending for a later pass —
  retiring it there would lose the sender's recovery path while the
  recipient never saw the event — pinned by
  `delivery_retains_obligation_when_no_relay_accepts`. A refused
  obligation retries every pass indefinitely: v0.2 has no ceiling,
  backoff, or attempt counter, so a permanently refusing relay
  means a permanently pending obligation, visible through the
  pending projection. The states:
  | Local send attempted | Not delivered — the bytes may have reached nobody |
  | At least one relay accepted | Relay-accepted: the fact's whole meaning |
  | Recipient received | Not guaranteed unless separately acknowledged |
  | Retention expired before recipient retrieval | Recovered by reconciliation: the recipient's gap statement triggers a retransmit from the sender's durable outbox, and the obligation retires on the statement evidencing possession — no relay re-push exists, and none is needed |
  Recipient receipt is never reported by the send path; anything
  needing it must build an acknowledgement above this boundary.
- **`SignerSession` trait**: the NIP-46 `sign_message` boundary
  (`trust.md` "NIP-46 remote signing"); a `nostr-connect`-style client
  implements it, tested here only against an in-memory fake key.
- **Deferred**: the `nostr-connect` session negotiation is wiring for
  whatever composes this crate — the traits above are the pinned
  boundary. (`wyrd-sync/src/control/nip46.rs` is wire codecs only;
  no session-negotiation implementation exists yet.) The live
  mailbox side is described from the composer perspective in
  `docs/architecture.md:176-178` (the `LiveMailbox` composition);
  this section describes the boundary it
  implements, so the two stop contradicting each other.

## Control-message recovery / forget contract (DG-3)

Normative. Answers one question: **what durable evidence allows the
sender to stop retrying a control message without risking permanent
loss?** The resend half is solved — sealed bytes persist before the
first send and every retry is byte-identical. The forget half is this
section: until it, `*Delivered` meant relay-accepted and nothing more,
and an obligation no relay accepted stayed pending indefinitely.
This section is the DG-3 gate artefact; it records the decision of
open discussion OD-2.

### The forget condition

The sender may retire an obligation for recipient R **only on durable
evidence that R's durable state subsumes the obligation's effect**. "Subsumes" is
per obligation class, and always about R's *state*, never about a
message R claims to have seen. Recipient durable state is evidence,
not acknowledgement of the specific envelope: the sender never asks
whether message M was "received"; it asks whether R's current
durable facts imply that replaying M cannot add anything. That is
what makes the scheme robust against duplicates and divergent
reconnects — and what makes the pull below the natural acquisition
mechanism rather than an add-on:

> No sender obligation is retired because a message was delivered,
> because a relay says it was delivered, or because a narrow
> heuristic says it probably arrived. It is retired only because
> durable recipient state demonstrates that the obligation is
> already subsumed.

- **Announcement (snapshot S → R):** R's durable state either
  contains a snapshot whose ancestry includes S, or contains
  whatever durable holding fact the reconciliation statement
  projects as "S held". The statement is the transport
  representation of that fact, never equivalent to the fact
  itself.
- **Transition (T → R):** R has durably committed T, or has
  durably committed a successor whose validated ancestry contains
  T. The successor case is a valid proof predicate, not a
  heuristic — validating the chain through T requires T — with
  one hard requirement: it must be incapable of a false positive.
- **Capability (epoch-E wrap → R):** R's committed capability set
  contains the wrap's install, as projected by R's reconciliation
  statement from that committed set. Knowledge alone never
  suffices — a known epoch without its secret authorizes nothing
  until the capability arrives.

Recovery requirements attach to the semantic class, not uniformly
to all envelopes (`object-model.md` decision 33): transitions and
capabilities carry the state machine itself, and their loss strands
protocol progress; loss of announcements does not strand the same
protocol state machine, so they follow later under their own
retirement tag. The 21c scope boundary below
reflects that ordering: transitions and capabilities retire first,
while announcement obligations stay pending until their own
retirement kind exists.

Retirement commits a new sender-side durable fact, one kind per
obligation class (`AnnouncementReconciled`,
`TransitionReconciled`, `CapabilityReconciled`): each names the
obligation identity, the recipient identity, and the authenticated
reconciliation statement identity (statement digest/version, plus
epoch/domain where the class requires it) it retired against, so
the retirement replays and audits. The wire format of the
statement is not solved here; the contract requires only that
"retired against" reference an authenticated durable-evidence
identity, never a bare message id. Pending
derives as queued minus (delivered ∪ reconciled), and the
per-class covered predicates treat all three sets as covered.
Redefining `*Delivered` instead is rejected: it would silently change
what every existing peer reads. The new-kind form costs a fact-tag
allocation per class (checked against the full tag set, as `0x16`
was) and an `upgrade-contract.md` entry, and is honest.

Two differences, different names. Sender-side pending is
`pending = sender obligations − sender completion facts`
(delivered ∪ reconciled): it drives the send loop.
Reconciliation computes
`missing = sender obligations − recipient durable-state evidence`:
it drives retirement. Formally, for obligation class C and
recipient R, let `O_C(R)` be the sender's durable outstanding
obligations for R and `H_C(R)` the reconciliation view projected
from R's durable state. An obligation `o ∈ O_C(R)` may be retired
iff `o ∈ H_C(R)`; the normative reconciliation result is
`O_C(R) \ H_C(R)`, and every element remaining in that difference
remains outstanding. Confusing the two retires obligations the
recipient never evidenced.

### Reconciliation safety invariant

> Optimizations may reduce what is retransmitted, but may not
> enlarge what is considered reconciled.

Full-comparison says reconciled while the optimization says not
merely retransmits (safe); the reverse is irreversible loss.
Class predicates above are admissible only as proven-equivalent or
conservative predicates, never as the definition. This is the
single most important implementation constraint in this decision,
and the acceptance tests pin it: no test may retire an obligation
the reference comparison would keep.

The sender's pending/reconciled state is durable independently of
the recipient's advertised view. Monotonicity is `pending →
reconciliation observed → reconciled committed → no longer
pending`, with no transition that can make an unproven obligation
disappear: a crash between observing reconciliation and committing
the reconciled fact resurrects the obligation (harmless
retransmission); the reverse ordering would lose it.

### Explicitly not evidence

Relay acceptance. Relay retention. Recipient liveness. A
transport-level ACK. Knowledge without possession. And a recipient
statement about a *message* ("I received #123") as opposed to
durable state: message-shaped receipts are rejected as the primitive
because they die to exactly the four failure modes this contract
must survive — crash between receipt and commit, relay expiry of the
receipt itself, duplicate delivery, and reconnect after divergent
progress.

### Retention assumption

Bounded: relay retention may be arbitrarily short, and nothing in
this contract depends on otherwise. Retained envelopes are
opportunistic recovery, never the correctness basis. This
assumption cannot be invalidated by a relay operator, and it
survives the retention-refusal decision (DG-4) landing with more
permissiveness than assumed — the protocol contract takes no
moving dependency on an unresolved implementation decision.
Bounded retention does not mean bounded obligation
lifetime: the obligation may remain pending indefinitely; what is
bounded is the lifetime of any particular relay copy. Relay
retention is a transport cache; durable reconciliation is the
correctness evidence — the relay is never a durable participant in
the protocol. Stated cost:
the send pipeline's "the relay retains every unacked envelope"
(`crash-consistency.md`) is an expectation, not a guarantee — see
that doc's qualified sentence.

### Reconciliation (the pull)

The sender learns R's durable state through a recipient-originated
reconciliation statement: R supplies an authenticated
reconciliation view derived from its durable state, the sender
compares that view against its obligations, and sends what remains
missing. Pull is not "give me your entire state" — it is "give me
enough authenticated projection of your state to reconcile this
class", which leaves room for chunking and pagination when
resource limits demand it. The statement is signed, over durable
state only, idempotent under redelivery (set-membership comparison, so
reconciling twice retires nothing new), and answered under a budget —
a recipient query must not oblige an unbounded response, and that
budget interacts with the resource-limits work rather than being
solved here. The pull covers what push cannot: relay retention is
irrelevant to a recipient that asks. This same primitive serves the
late-joiner case (superseded-epoch snapshot ids): "the recipient
does not know what it missed" gets one design, not two.

A relay acceptance behind a request marks only that the bytes left,
never that the peer opened them: a sender that has rotated past the
requester's newest held epoch answers `UnknownEpoch` and skips for
redelivery, indefinitely, while the requester treats the acceptance
as asked. "Asked and understood" versus "asked and permanently
skipped" are therefore different states, and only the recipient's
next statement — covering the re-sent obligations, or not —
distinguishes them. Diagnostics (21d) must render the distinction;
the request path itself stays an accelerator, never the sole path,
so the ambiguity costs retransmission, never loss.

The reconciliation view is a projection of durable facts, not
itself another authoritative store:

```text
recipient durable state
        ↓
reconciliation view
        ↓
set difference against sender obligation
        ↓
retransmit / retire
```

The wire format of the view may be optimized later without changing
retirement semantics, provided the projection stays conservative —
it may omit what the full comparison would use (causing
retransmission), never assert subsumption the durable facts do not
support.

Implemented as 21c (`runtime::respond`): the sender answers each
received statement once per process lifetime (a volatile answered
set; restarts re-answer idempotently), retiring what the evidence
covers and retransmitting — at most 32 sends per statement —
what it does not, through the existing deliver path with no new
wire kind. Transitions sealed past the recipient's newest
evidenced install are skipped, never retired, until the
capability install arrives (rotation framing is never skipped, so
the keys land first). Scope boundary, stated normatively: 21c
retires transition and capability obligations; announcement
obligations remain pending and are not eligible for
reconciliation retirement in 21c.

Surfaced as 21d: `sync status` carries a `reconciliation` row —
statements received plus transitions and capabilities retired,
all from committed facts, classes and counts only — and `sync now`
reports the open gap as two gauges: statements never evaluated,
plus evaluated-but-stuck ones whose requester is still owed. The
stall gauge fires if and only if an evaluated statement made zero
progress and its obligations are still owed at end of run — "owed
and undeliverable", never a claim about what the recipient opened,
which the sender cannot distinguish from delivered (relay
acceptance is the v0.2 guarantee). Both halves of the conjunct
matter: a statement that retired some obligations but could not
deliver the remainder records no stall, so partial progress leaves
an undeliverable remainder unnamed by this row — the remainder
stays pending, so the run still fails at the pass cap, but the
stall gauge does not attribute it. Concretely: an
`UnknownEpoch` skip records a stall at evaluation, but the pass's
unscoped delivery usually discharges the obligation right after
(relay acceptance commits `Delivered`), so the stall closes behind
it and reads zero — the sender has nothing left, and the
recipient's next statement re-opens the conversation if it is still
behind. What latches the gauge open is a zero-progress evaluation
whose obligations stay owed: an unresolvable transition or a
missing sealing key (no send path moves them, whatever the relay
does), or a live obligation for a relay that accepts nothing —
a send error aborts the pass after any retirements already
committed but before anything is marked, so the statement is
re-evaluated next pass (awaiting-answer until then) and only zero
acceptance flows through to a recorded stall. Still owed after
every pass, so the run fails and names it. The stall record
itself is volatile like the answered set; a restart re-derives it
from the durable request bucket.

### Acceptance scenarios (normative)

A reader with this contract and the code must be able to state, for
each case, whether the message is lost and what the sender does. A
contract that answers five and shrugs at two has not closed the
gate.

1. **Sender crash after sealing, before any send report.** The
   sealed bytes are durable before the first send, so the obligation
   survives by construction; a send report that never arrived leaves
   it pending. Normative, not just tested.
2. **Recipient crash after accepting, before durably committing.**
   No fact was committed, so the recipient's state proves nothing;
   if the relay still holds the envelope, at-least-once redelivery
   covers it (opportunistic, not correctness), otherwise the next
   reconciliation exchange must recover it — the recipient need
   not know that this particular envelope was lost. This case
   rejects message-shaped receipts: a receipt sent before the
   durable commit attests a message the recipient does not have.
3. **Relay retention expiry.** No acknowledgement can be produced
   or delivered. The recipient's durable state is the evidence and
   the relay is irrelevant; reconciling after expiry behaves
   identically to a delivery that was never relayed.
4. **Recipient offline longer than relay retention, then
   reconnect.** The reconnect is where the recipient discovers the
   gap — this is the pull path's raison d'être. No re-push path is
   required.
5. **Duplicate delivery.** Engines stay idempotent over redelivery;
   the forget contract must not weaken that, and reconciliation
   itself is duplicate-prone, so the comparison is set membership.
6. **Reconnect after both sides progressed independently.** The
   comparison is over state, not over messages — the one case a
   receipt cannot answer at all.
7. **Durable possession proof.** The contract names what the proof
   *is* — which durable facts, on the recipient, constitute it, per
   the subsumes predicates above — and the reconciliation statement
   is how the sender learns of it.

The reconciliation implementation has landed (21a–21c): the
operative rule is the forget condition above — an obligation
retires only on durable evidence the recipient's state subsumes
it, committed as a `*Reconciled` fact naming the proving
statement. Relay acceptance alone still retires nothing. The
unbounded refusal-retry position (`sync-and-peers.md:87-91`)
consequently narrows to its backoff half — "retries until evidence
arrives" — and the peer-repair loop consumes this contract's
vocabulary to distinguish "unavailable" from "never received".

## What is exchanged

- **Snapshot announcements** (small, fanned out to every admitted device): "my head set now
  includes snapshot S, and here is my current `node_addr` for retrieval" —
  signed, verified against known member identity keys (`trust.md`). The
  address is authenticated routing metadata inside the same sealed
  plaintext, never identity and never snapshot content (`fetch-on-open.md`).
  Freshness is operational, not validity: newer announcements do not
  cryptographically invalidate older ones — announcement history is
  append-only, and address selection/fallback is an operational layer
  decision. Ongoing announcements go to every other admitted device —
  members and readers alike — of the snapshot's bound transition, so
  admitted readers keep converging past admission; reader-authored
  announcements are rejected at intake, since readers author nothing.
- **Encrypted manifests** (hierarchical, per-subtree — see
  `object-model.md`): trees plus the content→storage mapping for every
  object the snapshot references, sealed to the drive. Drive members
  decrypt; vaults store them opaquely.
- **Objects** (ciphertext, addressed by StorageId): pulled on demand, not
  pushed.

Vaults see: opaque blobs, sizes, counts, timing, traffic patterns. Vaults
cannot determine plaintext equality from object representation, and never
see content IDs, paths, or tree structure.

**Layering note:** Wyrd chunks are logical storage/dedup units;
iroh-blobs' Bao chunking is transport verification with range requests and
resumable state. The two are deliberately separate abstractions — Wyrd
rides on iroh's verified streaming instead of duplicating it.

## Cross-device dedup (a manifest protocol, not a vault protocol)

1. Device has plaintext content C, derives ContentId.
2. Before encrypting and uploading, it consults manifests it has received:
   does any member's manifest already map C → some StorageId S?
3. If yes: fetch S, decrypt, verify (AEAD binding + content hash), done —
   no second upload. If no: encrypt with a fresh nonce, upload, publish the
   C → S mapping in its own manifest.

The vault learns nothing in either path. This protocol is why manifest
exchange is eager and object transfer is lazy.

## Two-phase content arrival

Metadata first, content later — and knowledge is layered, not binary. A
device can know history (a snapshot exists) without knowing structure (its
tree), know structure without knowing file metadata, and know metadata
without holding bytes. The materialization states below describe **residency
and policy only** — knowledge levels are tracked separately:

| State | Meaning |
|---|---|
| `REMOTE_ONLY` | known via manifest; content not local; no local storage |
| `CACHED` | content local, fetched by access; evictable by policy |
| `PINNED` | content local; guaranteed retained by user policy |

Fetching is progressive at the object level: an interrupted download leaves
only verified immutable chunks behind, so resume needs no special mechanism.

## Materialization policy vs peer role

Peer role and materialization are independent parameters:

- **Roles:** `vault` (replicates every object, never prunes) and `mirror`
  (participates in live sync, prunable).
- **Materialization policies:** `full`, `partial` (pinned paths), `on-demand`
  (cache-only with size cap).

A desktop is `mirror + full`; a laptop `mirror + partial`; a phone
`on-demand` with a pinned subset; a NAS `vault + full`. Pin/evict decisions
are local device policy — they change what the device holds, never what the
drive contains. The CLI surface for this is `wyrd pin` / `unpin` / `evict`
plus `wyrd cache status|policy` (`docs/cli.md`): policy facts stay in the
device's durable log and are never published. The CLI reports two policy
values, not three — fetched-by-access `CACHED` carries no retention promise
and collapses into `REMOTE_ONLY`; only an explicit pin promises retention.

## Encryption and keys

- Objects are encrypted client-side (per-object AEAD, fresh random nonce,
  AAD binding over version/kind/ContentId) before leaving the device — in
  transit and at rest. A wrong manifest mapping fails at the AEAD tag.
- Manifests are sealed to the drive; only admitted devices (members and
  readers) can interpret them.
- Snapshots are signed by their author device's identity key; peers reject
  unverifiable snapshots.
- The full key hierarchy, admission, removal, and rotation semantics are
  normative in `trust.md` — **that document gates sync-layer implementation**.

## Peer admission

Any member can author snapshots — authorization comes from membership
state, not drive creation. New devices join through admission and receive
capabilities; readers join through reader admission and receive the same
capabilities without authorship. Membership is signed,
replicated state that members agree on.

### Post-admission discovery (catch-up obligation)

The bootstrap invitation carries the genesis transition plus the
admission-epoch capability and nothing else. Learning everything after
that is a catch-up obligation on the admitter, not a second protocol:
a durable set of existing control messages, addressed to the newcomer
and retried until acknowledged.

- **Membership:** the authoritative chain suffix after genesis,
  replayed by the newcomer through the normal validation machinery —
  no privileged path, no trust in the pusher beyond signatures.
- **Capabilities:** one wrap per epoch, contiguous from the admission
  epoch to the current epoch. A sparse union is accepted only if the
  capability format and authorization rules prove it safe.
- **Heads:** current head announcements with their retrieval routes,
  re-sent byte-identical to the authors' signed statements.
- **Rotation notices** are informational; transitions plus
  capabilities are authoritative for epoch state.
- **Redundancy without authority:** any member that observes the
  admission may push the same set (intake dedupe makes repeats
  no-ops), but only the admitting authority's committed admission
  transition determines membership. Bootstrap changes
  discoverability, not authorization.
- **Ordering is an optimization:** intake already holds
  membership-unseen messages pending, so the newcomer converges
  regardless of mailbox delivery order. The invariant is eventual
  convergence under arbitrary order and duplication, proven by
  contracts 17–22 in `wyrd-contracts`.

Pre-admission history stays opaque to the newcomer by design: it
holds no old epoch secrets, so old snapshots and manifests are
unreadable to it (`trust.md` revocation boundary). The admission
commit and its catch-up obligations land in one durable batch, so a
crash cannot commit the former while losing the latter.

Known boundary, resolved: catch-up used to span only epochs the
invitation covers, because epoch-key delivery past the invitation was
circular under the envelope rules (a wrap for N+1 sealed under
envelope N+1, openable only with key N+1). Rotation delivery decides
it (option 2, ECDH to the registered key, `trust.md`): post-invitation
epochs converge through the rotation framing, and pre-key offers skip
transiently (retained, counted) until the settling drain goes quiet.
The sender side mirrors this: an obligation with nothing mintable
stays pending and observable via the pending projection instead of
failing its whole pass, and reused sealed bytes are verified against
their obligation before the send that would discharge them.

## Conflicts

No merging. Concurrent publishes create multiple heads; both remain
reachable. **DAG conflict and path conflict are distinct** — multiple heads
does not mean any path differs; the live view computes path-level
differences between heads and surfaces conflicted paths with both versions
(presentation is defined policy, not format). Resolution = publishing a new
snapshot whose parents are all heads. The `(timestamp, author)` tiebreak
orders versions for display only — it never decides content.

Version access is lookup grammar, never stored entries: a trailing `@N` on
a component (`foo@1`) addresses version N of a conflicted `foo`, numbered
deterministically in SnapshotId byte order. The grammar applies only where
the literal path does not exist — real stored names always win — and
`readdir` never lists version-qualified names. SnapshotIds themselves never
enter the user-facing path. Conflict version selection is a property of
path resolution, not of the stored filesystem namespace; the projected
namespace stays the user's data only (invariant 8 in `architecture.md`).

## Operational patterns

- Supervised tasks restart with capped exponential backoff
- Every event subscription has a drainer: an undrained subscription wedges
  the sync actor (do not regress this)
- Filesystem watchers declare a lag contract: on `Lagged`, backfill/reconcile
- Echo suppression for self-writes (hash + TTL) so the watcher never
  re-publishes what the peer just wrote
- Pause/resume defers work instead of dropping it

## FUSE behavior for non-local content (contract between sync and fuse)

The normative design for this boundary — demand channel, blocking open,
timeouts, daemon serving — is `fetch-on-open.md`. FUSE talks to an
abstract materialization interface — lookup, read,
ensure_local, publish — which an application composes from format + sync;
the filesystem layer never knows iroh exists. Internally the fetch state
machine is richer than the POSIX boundary it maps to:

```
RemoteOnly → Fetching → Available | Unavailable(generation) | Corrupt
```

The first three project live from durable state; `Unavailable` also
projects live once the engine's terminal evaluation completes a
generation: every representation cooled on failure evidence, with
the completed generation number attached. `Corrupt` projects only
when every exhausted representation cooled on verification
rejection. Neither survives a restart — both are memory-only attempt
state (`docs/peer-repair.md` Part 1). A new waiter reopens the
attempt as a new generation: the demand rides a sticky reopen note
(an unavailable read records one and fails fast; corrupt verdicts
complete waiters without noting — their repair is quarantine's),
drained by each pass's generation sweep. The translation to POSIX errors
happens only at the boundary: opening a non-local path blocks on
fetch with visible progress, serves the read once verified and
cached, and fails with `EIO` when no representation serves and the object
is not cached. A terminal generation completes its waiters with that
bounded `EIO` instead of the full deadline — unless a rejection
was observed for the identity within the repair window (30 s,
memory-only, unobservable to the reader), in which case the waiter
waits out the repair behind the stale projection instead of
failing fast on it. Corrupt or unreachable representations fall back to the
next recorded representation inside the fetch walk — and, within one
representation, its transport root before its storage address —
hash/AEAD-verified, never committed on mismatch. The store
verifies on read and fails closed; when locally held bytes fail
verification the read names the rejected representation
(`ViewError::RejectedRepresentation`, carrying the identity and
kind) to the loop's quarantine drain, which emits the diagnostic,
discards the bytes, and clears the possession claim — while the
`Cached` policy and the waiting reader survive, so the same read
re-demands the identity as a fresh generation
(`docs/peer-repair.md`, child 12). Corrupt authored structure
(undecodable trees, lying sizes) is not rejected bytes and still
fails `EIO` with no repair. The rest of the repair design —
generation-scoped terminal state, route-set policy, measurement
before replication — is recorded in `docs/peer-repair.md`.
Eviction never affects the drive — only what this device holds.
