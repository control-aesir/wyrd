# Membership and Epoch State Machine

**Status: DRAFT.** The final specification gate for `wyrd-sync`; promote to
normative together with `trust.md`. This doc answers: *what makes a snapshot
an authorized descendant of another snapshot?*

Design goals, in order:
1. **Offline-first** — no global agreement, no synchronous revocation;
   inconsistency is bounded and self-heals as state propagates.
2. **Exact revocation** — a removed device's write authorization ends at a
   precise, verifiable boundary.
3. **Membership privacy** — the membership graph never touches a public
   relay.

## The membership log

Membership is an **append-only chain of signed transitions**, sealed to the
drive (members decrypt; vaults and relays store opaquely):

```
MembershipTransition {
    epoch:      u64          // the epoch this transition creates
    prev:       hash of previous transition (None at genesis)
    changes:    Vec<Change>  // Admit | Remove | Rotate | SetOwners
    members:    membership root (content-addressed set after this transition)
    owners:     owner set
    author:     Nostr pubkey (must be in the owner set)
    signature:  Schnorr over "wyrd membership v1" || DriveId || canonical bytes
}
```

- **Epoch bump triggers:** admit, remove, rotate (compromise response),
  owner-set change. One transition = exactly one new epoch.
- `known_epoch(peer)` = the highest epoch present in its local copy of the
  log. There is no global epoch — each peer evaluates with what it knows.
- **v0: exactly one owner** ⇒ single writer ⇒ the log is linear. Two
  transitions claiming the same epoch is a **membership conflict**: an error
  state the owner resolves by re-signing; peers refuse both entries until
  resolved.
- The log chain is itself content-addressed: each entry names its
  predecessor, so tampering is detectable and history is append-only.

## Epoch secrets and capabilities

```
EpochSecret(N) derived per trust.md hierarchy
```

A **capability** delivered to a member of epoch N contains the wrapped
secrets for **epochs 1..=N** (so new members can read full history) — and
nothing beyond. A removed member retains exactly the epochs it ever held;
the epoch model makes that boundary exact. (The chain list is 32 bytes per
epoch — small; compact encodings are a later optimization.)

Delivery rides the Nostr mailbox: the owner can mint epoch N+1 and wrap the
new capability while the new/remaining device is offline.

## Snapshot authorization (the rule)

A snapshot S is evaluated by a peer with known epoch K:

```
authorized(S)  ⟺  signature verifies (drive-bound, author's Nostr key)
              AND author ∈ members(S.epoch) per the peer's membership log
              AND S.epoch ≤ K
```

Classification:

| Condition | Classification | Effect |
|---|---|---|
| `S.epoch == K`, author active | **authorized head candidate** | may advance canonical state |
| `S.epoch < K` (author removed in some epoch ≤ K) | **stale fork** | valid history; can never advance state; browsable, retained |
| `S.epoch > K` | **unverifiable yet** | hold; authorize when the log catches up |
| signature fails | **reject** | drop (and flag the sender) |

The two central semantics, restated precisely:

- **Valid signature ≠ valid current-state transition.** Ciphertext-valid
  work by a later-removed device remains a historical fork forever.
- **Bounded-fork:** while a peer still knows only epoch K = N, it may
  temporarily accept an epoch-N snapshot from a device that has been removed
  at N+1. When its log advances, the snapshot degrades from authorized to
  stale. This transient inconsistency is expected, safe (fails closed), and
  self-heals on propagation.

## Per-event behavior (state transitions)

| Event | Peer action |
|---|---|
| receive `MembershipTransition(N+1)` from owner | verify owner signature over the chain; unwrap the delivered capability; set known epoch = N+1; reclassify existing heads (authorized → stale where applicable) |
| receive snapshot claiming `S.epoch < K` | store as stale fork; never surface in live view |
| receive snapshot claiming `S.epoch == K` | authorize per rule; add to head set |
| receive snapshot claiming `S.epoch > K` | park until the log advances (object bytes may stream in meanwhile) |
| local write (member, epoch K) | publish snapshot at `epoch = K`; announce via control plane |
| local write observed at `known_epoch = K` while owner has minted K+1 | writes continue at K and become stale forks when K+1 arrives — this is the cost of offline operation and is acceptable (see Adoption) |
| membership conflict (two transitions, same epoch) | freeze membership evaluation; surface as drive-level error for the owner |

## Heads and reconciliation

- **Heads** = snapshots not referenced as a parent by any known snapshot.
- Live view renders **authorized heads only**. One authorized head = live
  state; multiple = conflicted (existing rule). Stale forks are visible
  through time travel, never in the live view.
- **Adoption is forbidden by default:** an authorized member may not parent a
  new snapshot to a stale fork or graft a stale fork's tree into the current
  state. Tradeoff, stated openly: a removed device's un-replicated final
  work is lost. If a legitimate member's work ends up in a stale fork
  (removal raced its writes), the owner may explicitly mint a recovery
  snapshot grafting specific content — an owner-signed, deliberate act,
  never an automatic one.
- Stale forks are never deleted (append-only); GC rules, when they exist
  someday, may revisit this.

## Edge cases

- **Removed then re-admitted (new Nostr key):** a new device with a fresh
  capability; nothing special.
- **Capability lost / fresh device restore:** re-pair via a new owner
  invitation (new epoch not required for mere re-delivery of the same
  epoch's secrets; a rotate is still recommended if the loss was a
  compromise).
- **Offline vault:** epochs are irrelevant to it — it holds ciphertext of
  every epoch and accepts fetches for any StorageId it stores.
- **Compromise response:** remove + rotate in one transition (new epoch,
  new epoch secret, old secrets allowed to remain historical).
- **Clock/hole in the log:** a peer missing log entries N..K cannot
  authorize snapshots in (N, K]; it parks them and fetches the missing
  entries — the log is small and control-plane-announced.

## Invariants

1. The membership log is append-only and owner-signed; every epoch has
   exactly one transition.
2. `authorized(S)` depends only on: the signature, the membership log state
   at/before `S.epoch`, and the evaluating peer's known epoch — never on
   wall-clock time or connectivity.
3. A stale fork can never become current state; adoption requires an
   explicit owner-signed recovery snapshot.
4. Membership evaluation is deterministic given (log, snapshot): two peers
   with identical knowledge reach identical verdicts.
5. Epoch secrets flow only to members of that epoch; capabilities never
   include future epochs.
