# Membership and Epoch State Machine

**Status: NORMATIVE.** Companion contract to `trust.md`, which owns identity,
custody, the key hierarchy, and capability confidentiality; this document
owns the authorization state machine. It answers: *what makes a snapshot an
authorized descendant of another snapshot?* — precisely, given a snapshot, a
membership log, and partial local knowledge.

Design goals, in order:
1. **Offline-first** — no global agreement, no synchronous revocation;
   inconsistency is bounded and self-heals as state propagates.
2. **Exact revocation** — a removed device's write authorization ends at a
   precise, verifiable boundary.
3. **Membership privacy** — membership contents never touch a public relay.

## Two predicates, never collapsed

Every snapshot evaluation separates:

- **Historical validity** — *is this a genuine snapshot, signed by a member
  authorized under the canonical membership state it commits to?* An
  intrinsic property of the snapshot against the log.
- **Current eligibility** — *is this snapshot permitted to advance canonical
  state now?* A property of the snapshot against the log **and** the local
  DAG and the peer's known membership state.

A removed device's old snapshot stays historically valid forever; it is
never eligible again. All state-machine semantics below hang off this split.
Classifications are distinct API states (an enum, never a boolean), and only
REJECTED means "invalid": VOIDED, SUPERSEDED, and STRANDED are valid
historical objects that cannot advance state.

## Layer 1 — the membership log

Membership is an **append-only chain of signed transitions**, sealed to the
drive (members decrypt; vaults and relays store opaquely):

```
MembershipTransition {
    epoch:        u64          // the epoch this transition creates
    prev:         hash of previous transition (None only at genesis)
    changes:      Vec<Change>  // Admit | Remove | Rotate | SetOwners
    members_root: hash of the member set AFTER applying changes
    owners_root:  hash of the owner set AFTER applying changes
    author:       Nostr pubkey
    signature:    BIP-340 over "wyrd membership v1" || DriveId || canonical bytes
}
```

A **membership state** is `(epoch, transition_id, members_root,
owners_root)`. A peer's authoritative knowledge is its **known membership
state** — the tip of the canonical chain — not a bare epoch number; the
epoch is a derived convenience. The genesis transition (epoch 1,
`prev = None`) is created with the drive; `members_root` and `owners_root`
both cover exactly the owner. Every epoch number has a state, so snapshots
can always reference one — the snapshot's membership reference is never
optional.

### Cryptographic validity of a transition

A transition is **valid** iff:

1. Structure: `epoch ≥ 1`; `prev` identifies a valid transition at
   `epoch − 1` (None only at genesis); `changes` is non-empty and every
   change is individually well-formed.
2. `apply(state(prev), changes) == (members_root, owners_root)` — the
   resulting roots are **derived, not independently authoritative**; the
   verifier recomputes them. Change rules:
   - `Admit(d)` requires `d ∉ members`; `Remove(d)` requires `d ∈ members`.
   - `SetOwners(D)` requires `|D| == 1` in **v0** (singleton ownership;
     multi-owner is a later extension that relaxes exactly this rule) and
     the device must be a member. Owners are a subset of members.
   - `Rotate()` changes no member or owner; it exists to force a fresh
     epoch secret (compromise response).
3. `T.author` is an owner **in the pre-transition state** (`state(prev)`).
   Signature authority always comes from the state being left — this is
   what makes `SetOwners` and removing the last current owner expressible.
4. `T.signature` verifies, drive-bound, with full BIP-340 key validation
   (`lift_x` on the x-only pubkey; exactly 64-byte signatures) — exact
   message bytes in `trust.md`.

Validity is a property of the object against its predecessor; **canonical**
is a separate, chain-level property below.

### Canonicality and conflicts

The **canonical chain** is defined by the local log:

- The canonical transition at epoch 1 is the unique valid genesis.
- The canonical transition at epoch N+1 is the unique valid transition
  whose `prev` is the canonical transition at epoch N.
- If two or more valid transitions claim epoch N (with any predecessor), a
  **membership conflict** exists at N: none of them is canonical yet, and
  membership evaluation **freezes** (snapshots bound to any of them are
  PENDING; a drive-level error is surfaced for the owner). Peers never pick
  a side themselves.
- A conflict resolves when exactly one of the contested branches acquires a
  unique valid continuation: that branch — and its ancestors back to
  genesis — become canonical; every sibling branch is **voided**
  permanently. If both branches acquire continuations, the conflict simply
  recurs at the next epoch and the same rule applies; the freeze moves up
  until one branch is uniquely extended.
- The chain is therefore append-only and self-selecting: canonicality is
  recomputed to a fixed point from the tip whenever the log changes, and is
  determined **solely by the log** — never by snapshot DAG state.

Voided transitions are retained forever as historical objects; they cannot
be deleted or re-signed. v0 has exactly one owner ⇒ a single writer ⇒
conflicts indicate device duplication or a bug and are treated as errors,
not tolerated forks.

### Terminal state: zero owners

`Remove(owner)` when the owner is the only owner is a **valid** transition,
but it terminates the drive's owner-authorized evolution: authority always
comes from the pre-transition owner set, so with an empty owner set no
future transition can ever be authorized. Membership freezes permanently
(no admit, no rotate, no recovery snapshot). Recovery of such a drive
requires the root custody / guardian mechanism (`trust.md`), which is
reserved and post-v0. Implementations MUST warn before applying a
last-owner removal.

### Epoch bump triggers

Admit, remove, rotate, owner-set change. One transition = exactly one new
epoch.

## Layer 2 — epoch secrets and capabilities

```
EpochSecret(N): fresh random 256-bit secret, generated by the owner at
                transition N; never derived from the DriveRootKey, the epoch
                number, or any other epoch's secret, and NEVER reused
                across transitions — even two transitions with identical
                resulting membership state each get an independent secret
                (a Rotate always yields a new secret).
```

The root key authorizes and protects custody; it is **not** a master key
for epoch material — a member holding the root could otherwise derive every
future epoch and revocation would collapse. **Ordinary members never
possess the DriveRootKey**; it lives only in owner/recovery custody (wrapped
at rest per `trust.md`). Key derivation from the epoch secret is per
`trust.md`.

A **capability** delivered to a member of epoch N:

- contains the wrapped secrets for **epochs 1..=N** (new members read full
  history) and nothing beyond;
- is cryptographically bound to `(DriveId, recipient DeviceId, transition
  id, epoch)`: the wrapping AEAD's associated data is
  `domain("wyrd capability v1") || DriveId || recipient DeviceId ||
  transition_id || epoch`, so a capability cannot be transplanted or
  replayed across drives, epochs, or devices — tag verification fails in
  any other context;
- is delivered via the Nostr mailbox, so the owner can mint epoch N+1 and
  wrap the new capability while the device is offline (the pairwise
  transport scheme is a control-plane implementation detail; the AAD
  binding above is the contract).

**Capability installation is monotonic:** installing a capability may only
add secrets for epochs the device does not yet hold. It must never decrease
the device's known membership state, remove newer secrets, or roll back —
a replayed older capability is a harmless no-op, not a downgrade.

Security properties, stated as invariants:

1. **Forward secrecy against revocation:** possession of epoch N secrets
   does not permit computing epoch N+1 secrets.
2. **Historical access is explicit:** access to past epochs comes only from
   secrets a capability explicitly contains.
3. **Revocation bounds acquisition, not possession:** removing a device
   prevents it acquiring later-epoch secrets. It cannot revoke secrets,
   ciphertext, manifests, or plaintext the device already holds.
   (The chain list is 32 bytes per epoch — small; compact encodings are a
   later optimization.)

## Layer 3 — snapshot authorization

Snapshots commit to the **exact membership transition that authorizes
them**, not merely to an epoch number. The snapshot carries a membership
reference (`Snapshot` format in `object-model.md`) with the validity
requirement `S.epoch == S.membership.epoch`. An epoch number says *when*;
the membership reference says **which authorization state**. Both are
covered by the snapshot signature.

`timestamp` is display/tiebreak metadata only: it MUST NOT participate in
authorization, conflict resolution, membership ordering, or key derivation.

Predicates, evaluated by a peer over its local DAG and canonical chain
(non-circular; recursion terminates on the acyclic DAG):

```
historically_valid(S)  ⟺  BIP-340 signature verifies (drive-bound, full
                           key validation, exact message bytes)
                       AND T = transition(S.membership) is known and canonical
                       AND S.epoch == T.epoch
                       AND S.author ∈ members(T)

in_live_lineage(S)     ⟺  historically_valid(S)
                       AND (S has no parents                 // genesis snapshot
                            OR every parent P:
                                 in_live_lineage(P)
                                 AND P.epoch ≤ S.epoch)

eligible_head(S)       ⟺  in_live_lineage(S)
                       AND S.epoch == K
                       AND S is a DAG head
```

where K is the epoch of the peer's known membership state (the canonical
tip). `in_live_lineage` is the **ancestry rule** in executable form: a
member may only parent onto live-lineage snapshots. The membership layer
decides which transition is canonical; the snapshot layer only ever
operates against canonical states.

Same-epoch ancestry, settled explicitly:

- **Chains within one epoch are normal** (offline commits): `S1 → S2 → S3`
  all at epoch K is the expected shape.
- A new snapshot may parent onto **any subset of the live-lineage heads it
  knows** — including a merge of multiple heads (all parents must be
  live-lineage; `P.epoch ≤ S.epoch` covers same-epoch and older parents).
- Parenting onto a snapshot that is *not* live-lineage is forbidden — that
  is the adoption rule. There is no notion of one epoch-K snapshot
  "superseding" another at the same epoch; they coexist as parallel heads
  until a descendant merges or the epoch advances.
- "Head" always means DAG head (no descendants); eligibility is per
  snapshot, and becoming a parent merely removes a snapshot from the head
  set.

Classification:

| Condition | State | Effect |
|---|---|---|
| malformed / signature or key validation fails | **REJECTED** | drop (and flag the sender) |
| referenced transition unknown, contested (conflict freeze), or a parent unknown | **PENDING** | park; re-evaluate when the log/DAG catches up |
| signature valid but referenced transition voided, or author ∉ members(T) | **VOIDED** | retained; its authorization state never canonically existed; content only via recovery |
| `in_live_lineage`, `epoch == K`, DAG head | **ELIGIBLE** | may advance canonical state |
| `in_live_lineage`, not an eligible head | **canonical history** | the accepted past |
| valid history, `epoch < K`, not live-lineage | **SUPERSEDED** | stale fork; browsable via time travel, never live |
| valid history, `epoch == K`, not live-lineage | **STRANDED** | legitimate work on a doomed fork; owner recovery is the remedy |

Terminology note: **superseded ≠ revoked-author.** A snapshot becomes
superseded because its epoch's canonical chain moved past it, whether or not
its author was removed. An old snapshot by a still-active member is
superseded exactly like one by a removed device.

**Stranding is inherited and permanent:** a descendant of a superseded (or
stranded) snapshot has a non-live-lineage parent, is therefore never
live-lineage, and becomes stranded or superseded in turn. Descendants of
dead forks are never reclassified back, and implementers must not add
recursive rescue logic. Recovery grafts *content*, never *lineage* — that is
the only path back.

The two central semantics, restated:

- **Valid signature ≠ valid current-state transition.** Ciphertext-valid
  work by a later-removed device remains valid history forever; it cannot
  advance canonical state past the revocation boundary.
- **Bounded-fork:** while a peer still knows only epoch K = N, it may
  temporarily accept an epoch-N snapshot from a device removed at N+1. When
  its log advances, the snapshot degrades from eligible to superseded. This
  transient inconsistency is expected, safe (fails closed), and self-heals
  on propagation.

**The stranded-descendant case, stated deliberately:** a peer that has not
yet learned of a removal may build on a snapshot that later becomes
superseded, stranding the peer's own (perfectly legitimate) work along with
it. This is accepted, not an oversight. The owner's recovery snapshot is the
single sanctioned remedy.

## Per-event behavior

| Event | Peer action |
|---|---|
| receive valid `MembershipTransition(N+1)` | validate; if it extends the canonical tip, unwrap the delivered capability (monotonic install); known membership state = N+1; recompute canonicality; reclassify heads |
| receive valid transition not extending the canonical tip | retain; it creates or extends a conflict — freeze evaluation at that epoch, surface drive-level error |
| receive snapshot bound to unknown/contested transition | PENDING |
| receive snapshot bound to a voided transition, or author ∉ members | VOIDED (retained, never eligible) |
| receive snapshot claiming `S.epoch == K` | evaluate `eligible_head`; eligible heads join the head set |
| receive snapshot claiming `S.epoch > K` | PENDING; park until the log advances (object bytes may stream in meanwhile) |
| local write (member of canonical epoch K) | parent onto locally live-lineage heads; publish with `membership` bound to the canonical epoch-K transition; announce via control plane |
| local write at K while owner has minted K+1 | writes continue at K and become superseded when K+1 arrives — the cost of offline operation, accepted |
| membership conflict | freeze; drive-level error (see Canonicality and conflicts) |

## Heads, live view, and recovery

- **Heads** = snapshots not referenced as a parent by any known snapshot.
- The live view renders **eligible heads only**. One eligible head = live
  state; multiple = conflicted (existing rule). Superseded, stranded, and
  voided snapshots are visible through time travel, never in the live view.
- **Recovery snapshots** are the formal exception to strandedness, and they
  honor the ancestry rule anyway: they are owner-authored snapshots whose
  DAG parents MUST be current eligible heads and whose tree is rebuilt from
  **explicitly identified recovered content** — content/tree objects
  referenced directly by ContentId from any historical epoch for which the
  owner holds decryption capability. Recovery never parents onto superseded
  or stranded history: the owner is deliberately republishing specific
  bytes under the current epoch, not adopting a fork. It is always an
  owner-signed, deliberate act, never automatic.
- Owner recovery visibility: the owner can recover only content it can
  decrypt — historical epoch secrets are in its capability only if it has
  been continuously a member. Recovery resurrects bytes, not the old fork's
  lineage.
- Superseded, stranded, and voided objects are never deleted (append-only);
  GC rules, when they exist someday, may revisit this.

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
  fresh epoch secret, old secrets remain historical).
- **Clock/hole in the log:** a peer missing transitions N..K cannot
  evaluate snapshots in (N, K]; it parks them as PENDING and fetches the
  missing entries — the log is small and control-plane-announced.

## Invariants

1. The membership log is append-only and owner-signed; per epoch at most
   one transition is **canonical**, though several may be cryptographically
   valid; canonicality is determined solely by the log and recomputed to a
   fixed point from the tip.
2. Transitions are authorized by the **pre-transition** owner set; their
   resulting member/owner state is deterministically derived from
   `prev` + `changes` and committed via roots that verifiers recompute. v0
   enforces singleton ownership; removing the last owner is valid but
   terminal.
3. Every snapshot commits to the exact membership transition that
   authorizes it; eligibility requires the **canonical** transition of the
   peer's known epoch — an epoch number alone never authorizes anything.
4. Authorization evaluation is deterministic given (log, DAG, known
   membership state): two peers with identical knowledge reach identical
   verdicts. It never depends on wall-clock time — `timestamp` is
   display-only — or connectivity.
5. `in_live_lineage` is non-circular (recursive over DAG ancestors only);
   superseded/stranded/voided snapshots can never become current state; the
   only path back is an owner-signed recovery snapshot grafting explicit
   content onto eligible heads.
6. Epoch secrets are fresh random values, unique per transition; they flow
   only to members of that epoch; capabilities never include future epochs,
   are AAD-bound to (drive, device, transition, epoch), and install
   monotonically.
7. Ordinary members never possess the DriveRootKey.

## Conformance tests (the contract's test list)

These are the behaviors the state machine must be tested against before
implementation is considered conformant.

**Membership:** genesis transition; invalid genesis `prev`; epoch gap; wrong
predecessor; wrong author; author owner *before* the transition (valid) vs
author made owner *by* the transition (invalid); author removed by the
transition (invalid); remove last owner (valid, terminal); invalid
`SetOwners` (non-member, multiple owners in v0); duplicate admission;
duplicate removal; empty changes; valid `Rotate`; rotation produces a
distinct epoch secret; conflicting transitions with same predecessor;
conflicting transitions with different predecessor; conflict resolution by
extension; conflict followed by another conflict.

**Snapshots:** valid snapshot; bad signature; wrong DriveId; invalid pubkey
(fails `lift_x`); unknown membership transition; transition from a voided
branch; author not in committed membership; epoch/membership mismatch;
snapshot bound to a noncanonical (contested) transition; valid old snapshot
after revocation; old snapshot becomes superseded when the log advances;
same-epoch child of an eligible head; same-epoch child of a non-live-lineage
head; descendant of a superseded snapshot; snapshot with unknown parent;
merge of eligible heads; merge including a stranded head; recovery from
stranded content; determinism: identical (log, DAG) ⇒ identical verdicts.

**Capabilities:** correct recipient; wrong recipient; wrong DriveId; wrong
epoch; wrong transition; replay of an older capability (no-op, no
downgrade); replay after removal (no future secrets); capability containing
future epoch secret (invalid); capability containing the DriveRootKey
(invalid by construction); missing historical epochs in a fresh member's
capability (invalid — must be 1..=N).
