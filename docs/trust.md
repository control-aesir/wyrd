# Trust Model and Key Hierarchy

**Status: NORMATIVE.** This document owns identity, custody, the key
hierarchy, cryptographic constructions, capability security properties, and
control-plane security. The **authorization state machine** — membership
transitions, snapshot authorization, classification, recovery — is defined by
the companion contract `epochs.md`, which this document defers to.

The boundary this document owns: **drive membership → keys → manifests →
Content IDs → Storage IDs → device authorization.**

Governing principle:

> **Nostr provides identity and asynchronous authenticated messaging. Wyrd
> provides authorization, encryption, content identity, and storage.**

## Identity: the Nostr boundary

Wyrd does not define a device identity system. A Wyrd device identity **is**
a secp256k1 public key using Nostr-compatible key identity conventions;
snapshot authorship and membership authorization use **BIP-340 Schnorr
signatures** (secp256k1, 32-byte x-only public keys, 64-byte signatures,
standard BIP-340 tagged-hash challenge over the Wyrd message bytes, with
**deterministic nonces** — no auxiliary random input, which also makes the
signature — and therefore any id derived over it — a stable function of the
key and message). No Nostr event serialization, no SHA-256 event IDs.

The boundary, stated as a rule:

> **Nostr answers "who are you?" Wyrd answers "what are you authorized to
> decrypt?"**

- **secp256k1 + BIP-340: yes. Nostr event format: no.** Snapshots remain Wyrd
  canonical objects (`wyrd ‖ version ‖ kind ‖ payload`, BLAKE3 domain
  separation). We reuse the keypair and BIP-340 signature scheme, not
  Nostr's event serialization or its SHA-256 event IDs.
- **No social Nostr.** No profile metadata, follows, NIP-05, public relay
  presence, or social graph is required. A participant is a secp256k1
  keypair using Nostr conventions.
- **Membership contents are never public.** Membership, invitations,
  capability distribution, and rotation travel only in encrypted channels.
  Two confidentiality claims are distinguished deliberately:
  - **Payload confidentiality** (guaranteed): a public relay never learns
    "pubkey A is a member of drive X" from message contents.
  - **Metadata confidentiality** (best-effort, out of scope for the crypto
    layer): relay-visible routing patterns can still suggest relationships
    between pubkeys. Traffic analysis is not resisted here, exactly as for
    vaults.
- **NIP-44 carries the control plane, never objects.** Object encryption is
  Wyrd's own AEAD hierarchy (below); NIP-44 is the control-plane transport
  encryption (see Cryptographic substrate).
- **Device identity is immutable.** If a Nostr key is rotated, that is a new
  device: remove the old membership, admit the new key. Nostr's social
  identity-continuity conventions are not inherited.
- **NIP-46 remote signing is optional, scoped, and default-deny** (see
  below): the signing key may live in a hardware signer, phone, or bunker
  while the Wyrd daemon requests signatures. Wyrd never receives the nsec.

Three distinct uses of Nostr, kept separate:

| Use | Carries |
|---|---|
| public | identity (pubkeys), optional discovery/relay hints |
| encrypted control plane | membership changes, invitations, capabilities, rotation, snapshot announcements |
| direct P2P (iroh) | objects, manifests, bulk data |

## Cryptographic substrate: reuse implementations, own the protocol (decided)

> **Wyrd reuses standardized cryptographic primitives and audited
> implementations from the Nostr/secp256k1 ecosystem, and defines its own
> object formats, authorization semantics, and key hierarchy.**

Never implemented by Wyrd — MUST come from a maintained, audited
cryptographic library (the Rust `nostr` crate ecosystem provides all of
these): secp256k1 arithmetic, point validation / `lift_x`, BIP-340
sign/verify, private-key generation, ECDH, HKDF, ChaCha20, HMAC, CSPRNG.

Wyrd owns — the actual security surface, and where the design budget goes:
membership transitions, epoch semantics, capability semantics, revocation,
snapshot authorization, canonical serialization, DriveId binding,
ContentId/StorageId, the object encryption hierarchy, conflict resolution,
recovery.

Rules:

- Implementations MUST use a conformant BIP-340 implementation from a
  maintained cryptographic library; Wyrd MUST NOT implement secp256k1
  arithmetic or BIP-340 itself. The validity rules stated in this document
  (`lift_x`, 64-byte signatures, tagged-hash challenge) are protocol
  requirements a conformant library already enforces — verification must
  not bypass them.
- Wyrd specifies *what gets signed* (`M = domain ‖ DriveId ‖ signing
  preimage`, below); the library provides `sign(sk, M)` / `verify(pk, M,
  sig)`.
- **Control-plane transport encryption is NIP-44** (ECDH + HKDF-SHA256 +
  ChaCha20 + HMAC-SHA256, CSPRNG nonces), as exposed by the same crate
  ecosystem; relays see only Nostr routing metadata. NIP-04 is deprecated
  and MUST NOT be used. NIP-44's documented pairwise limitations (no
  forward secrecy / post-compromise security) are acceptable for control
  messages: the epoch/capability model — not the transport — carries the
  revocation boundary.
- Drive objects are never NIP-44: object encryption uses standard
  AEAD/KDF crate primitives directly with Wyrd's per-object construction.
- Capability wrapping reuses the same primitive set (secp256k1 ECDH →
  HKDF-SHA256 → AEAD) with the Wyrd AAD context binding — audited building
  blocks, Wyrd-defined semantics.
- NIP-46 remote signing (below) rides `nostr-connect`-style tooling; the
  daemon still never holds the nsec.

## Principals

| Principal | Identity | Purpose / Holds |
|---|---|---|
| drive | `DriveId` — random 256-bit, immutable | logical encrypted namespace; distinct from every other identifier |
| device | Nostr public key (`DeviceId`) | a Wyrd participant; holds a wrapped drive capability + its Nostr signing key |
| owner | one or more Nostr public keys | membership administration (v0: exactly one owner; owner *sets* and threshold policies are a later extension this model already accommodates) |
| vault | transport identity only | stores ciphertext; holds no keys, no Wyrd authorization |

Every identifier answers a different question — this separation is deliberate:

```
DriveId      "which logical drive?"
Nostr pubkey "which participant?"
ContentId    "which logical content?"
StorageId    "which physical encrypted representation?"
```

## Root custody (decided)

The Drive Root Key is a **random 256-bit secret, not a passphrase
derivative**. The passphrase is a key-*encryption* mechanism, not the source
of cryptographic identity:

```
random DriveRootKey
    │
    ▼
wrapped with a key derived from the user's passphrase
    │
    ▼
local Wyrd keystore (OS secure storage where available)
```

Changing the passphrase re-wraps the root key — the drive's cryptographic
universe is untouched. Hardware-backed unwrapping (Secure Enclave / TPM /
OS keychain) is a later storage upgrade that changes nothing about the
format.

**Root possession is an owner/recovery invariant.** The DriveRootKey is
never distributed as part of an ordinary member capability; it lives only in
owner custody (wrapped at rest). A member holding the root could otherwise
derive every future epoch and revocation would collapse.

**Deferred:** multiple owners, Shamir/threshold recovery. Those are a
*recovery architecture* (share lifecycle, quorum UX, backup procedures), not
a prerequisite for the storage architecture.

## Epoch keys: fresh secrets, not a root KDF

Membership epochs are the revocation primitive. A **membership change
creates a new epoch**; keys are derived from the *epoch secret*. The root is
**custody, not authority**: it protects drive-level cryptographic custody
and recovery material. Membership-transition authorization is provided by
the owner's Nostr signing key — the root never signs or derives
transitions. The shape is:

```
Drive Root Key (random, passphrase-wrapped at rest; owner/recovery custody)
    │  protects custody and recovery material — never derives epoch
    ▼  material, never signs transitions
Epoch Secret (fresh random 256-bit per membership epoch, minted by the owner)
    ├─ ManifestKey  = KDF(epoch secret, "manifest", ...)
    └─ ObjectKey    = KDF(epoch secret, "object", ContentId, kind, version)
    └─ (snapshot manifest keys derive from the epoch secret + snapshot id)
```

**Epoch secrets are fresh random secrets** — not `KDF(DriveRootKey, N)` and
not derivable from each other. A new uniformly random 256-bit secret is
generated for every transition; implementations MUST NOT intentionally
reuse an epoch secret across transitions (accidental collision is
negligible by construction). The owner distributes each new secret inside
wrapped capabilities. This is what makes the revocation boundary exact:

- **Forward secrecy against revocation:** possession of epoch N secrets does
  not permit computing epoch N+1 secrets.
- **Historical access is explicit:** access to past epochs comes only from
  secrets a capability explicitly contains (capabilities carry epochs
  `1..=N`; see `epochs.md`).
- **Revocation bounds acquisition, not possession:** a removed device keeps
  everything it already held — secrets, ciphertext, manifests, cached
  plaintext — and can obtain nothing later.

Rules:

- **Rotation creates a new cryptographic epoch; it never rewrites immutable
  historical objects.** Old objects remain encrypted under their old epoch;
  new material is unreadable to devices that hold only old-epoch
  capabilities.
- A device removed at epoch N cannot obtain epoch N+1 secrets — the epoch
  secret is distributed only to the members of that epoch, via wrapped
  capabilities.
- Per-object derivation keeps any member able to decrypt any object of its
  epoch; no pairwise keys exist.
- Per-snapshot manifest keys (`KDF(epoch, "manifest", snapshot_id)`) let
  revocation be as fine-grained as snapshots without a global key change.
- **A fresh epoch secret is minted for every transition** — never reused,
  even when two transitions produce identical membership state (a `Rotate`
  always yields a new secret).

## Control plane: Nostr is the mailbox, iroh is the data plane (decided)

**Both transports, different responsibilities:**

- **Nostr = asynchronous, authenticated control plane.** Invitations,
  membership changes, rotation announcements, and snapshot announcements.
  This is what makes the offline-vault/offline-device case work: the owner
  can authorize a new phone while it sleeps; the phone discovers its
  encrypted invitation later and joins.
- **iroh = live Wyrd protocol and bulk data.** Manifest requests, object
  transfers, ranges, synchronization, acknowledgements. Nostr is never the
  authoritative sync transport, and bulk state never flows through it.

Wyrd defines its **own control message types** — `Invitation`,
`MembershipChange`, `KeyRotation`, `SnapshotAnnouncement` — as Wyrd payloads
that encrypted Nostr events merely *transport*. What each layer exposes is
stated precisely:

```
Nostr-visible (relay metadata):
    sender pubkey, recipient routing, event timing/counts

Encrypted (opaque to relays):
    DriveId, membership transitions, capabilities,
    epoch secrets, invitation details
```

The exact routing mechanism (how a recipient discovers its messages without
leaking drive correlation) is a control-plane protocol decision, deferred.
Replacing Nostr as the rendezvous mechanism would not change Wyrd's
cryptographic model.

## AEAD binding (decided construction)

Every ciphertext is authenticated not only as bytes but as *an object of a
specific kind and logical identity*:

```
AEAD(
    key    = object_key (epoch-derived, above),
    nonce  = fresh random per encryption,
    aad    = format_version || object_kind || ContentId,
)
```

Storage ID = domain-separated hash over `nonce || ciphertext || aad`.

Invariant: **successful decryption alone is never sufficient.** A device
accepts an object only when (a) the AEAD tag verifies over the bound AAD,
and (b) the plaintext hashes to the expected Content ID. Two independent
checks, either of which catches a mismatched manifest mapping. The epoch is
implicit in the key. Re-encryption under a new epoch produces a new
ciphertext, a new Storage ID, and a manifest update — the Content ID never
changes.

**Cross-epoch reuse rule:** because the same logical content can exist under
multiple Storage IDs (one per encryption epoch), manifest mappings record
their encryption epoch, and a content→storage mapping is **reusable by a
device only if it holds the capability for that mapping's encryption
epoch**; otherwise the device re-encrypts under its current epoch and
publishes a new mapping. Fetching an un-decryptable representation is
meaningless (and fails the two checks above anyway).

## Snapshot authorization (decided; state machine in `epochs.md`)

The snapshot commits to the **exact membership state that authorizes it**:

```
Snapshot {
    parents:    Vec<SnapshotId>
    tree:       ContentId of root tree
    author:     Nostr public key (the DeviceId)
    membership: hash of the MembershipTransition whose state authorizes it
    epoch:      u64 — must equal the referenced transition's epoch
    flags:      u8 (bit 0 = recovery snapshot; see epochs.md)
    timestamp:  u64 (ms, HLC-ordered, display/tiebreak only)
    signature:  BIP-340 signature over
                "wyrd snapshot v1" || DriveId || signing preimage (below)
}
```

An epoch number says *when*; the membership reference says **which
authorization state**. Both are covered by the snapshot signature.

**Exact signing construction.** BIP-340 is byte-exact; implementations use
a conformant library (Cryptographic substrate, above) and never reimplement
the scheme. What Wyrd specifies is the exact input. The message is defined
over a **signing preimage** — a dedicated
canonical encoding of the signed fields, *not* "the envelope minus the
signature" (that would leave two parseable schemas and a reconstruction
hazard). The preimage is fully self-delimiting: every vector is a `u32`
little-endian element count followed by exactly that many canonical
elements; every other field is fixed-width little-endian; fields appear in
the declared order:

```
M_snapshot   = ASCII("wyrd snapshot v1") || DriveId(32 bytes)
               || snapshot_signing_preimage(parents, tree, author,
                                            membership, epoch, flags, timestamp)
M_membership = ASCII("wyrd membership v1") || DriveId(32 bytes)
               || transition_signing_preimage(prev, resolves, changes,
                                              members_root, owners_root,
                                              author, epoch)
```

`transition_id` = domain-separated BLAKE3 over the signing preimage ‖
signature (stable, because signatures are deterministic). Key validation
(`lift_x`, exactly 64-byte signatures, BIP-340's tagged challenge hash and
verification equations) is a protocol requirement enforced by the conformant
library; verification must never bypass or weaken it.

BIP-340 signs a 32-byte message; the Wyrd **challenge** is pinned so all
implementations agree byte-for-byte:

```
challenge_snapshot  = BLAKE3-derive_key("wyrd snapshot challenge v1",  M_snapshot)
challenge_membership = BLAKE3-derive_key("wyrd membership challenge v1", M_membership)
```

Signatures use **canonical BIP-340 nonces** (no auxiliary randomness), so
the same (key, message) always yields the same signature and ids stay
stable. Verification must use the same challenge derivation and full key
validation.

`timestamp` is display/tiebreak metadata only: it MUST NOT participate in
authorization, conflict resolution, membership ordering, or key
derivation.

The core rule:

> **A snapshot commits to the membership-log state that authorizes it, and
> historical validity is evaluated against that committed state; current
> eligibility is evaluated against the peer's local knowledge.**

Two predicates, never collapsed (full definitions and the classification
state machine in `epochs.md`):

- **Historically valid** — genuine signature, valid *and rooted* membership
  transition, author a member of the committed state. Intrinsic to the
  snapshot against the log; it does not depend on canonicalization
  outcomes. `authorized(S)` = historically valid **and** the referenced
  transition is canonical.
- **Currently eligible** — authorized, at the peer's known membership
  state, with ancestry satisfied (live lineage). Only eligible heads
  advance the live view; membership canonicality is advanced only by
  transitions.

Consequences:

- **Valid signature ≠ valid current-state transition.** A snapshot signed by
  a removed device, bound to the pre-removal membership state, remains
  historically valid forever — but is superseded once the peer's log
  advances, and superseded forks can never enter the live view.
- **Bounded-fork semantics.** Propagation races are expected and bounded:
  while a peer hasn't yet learned a removal (epoch N → N+1), it may
  temporarily accept the removed device's epoch-N snapshots; once the
  membership state advances, those branches become superseded forks.
  Global instantaneous revocation is impossible in an offline-capable system
  and is not a goal.
- **Stranding is accepted:** work built on a snapshot that later becomes
  superseded is stranded with it — legitimate or not — and is recovered only
  by a recovery snapshot (recovery flag, current canonical owner) grafting
  content onto eligible heads. Never lineage adoption.

The precise state machine — transition validation, membership conflicts,
snapshot classification, recovery — is normative in `epochs.md`.

## Device admission (decided)

- The owner mints a **device capability** — the wrapped epoch secrets plus
  registration of the member's Nostr pubkey — and **signs the membership
  transition** with the owner's Nostr key. Transition authority always comes
  from the **pre-transition** owner set (so owner-set changes and removing
  the last current owner are expressible); validation rules and the
  deterministic `apply(prev, changes)` construction are normative in
  `epochs.md`. The membership record reads:
  `pubkey, status = active, admitted_by = <owner pubkey>, epoch`.
- Membership is signed, encrypted, replicated state: members agree on who is
  a member of which epoch, and membership *contents* never reach a public
  relay (payload vs metadata confidentiality, above).
- **Capability construction.** AAD binding alone is not recipient
  authentication: the capability is wrapped under a key established by
  **secp256k1 ECDH** between a fresh owner-ephemeral key and the recipient
  device's x-only public key (HKDF to the AEAD key — secp256k1 signing
  keypairs double as ECDH identities), with associated data
  `domain("wyrd capability v1") || DriveId || recipient DeviceId ||
  transition_id || epoch`. The AAD binds the context; the ECDH-wrapped AEAD
  is what actually authenticates the recipient. **Installation is
  monotonic:** installing a capability may only add secrets for epochs not
  yet held; it must never decrease the device's known membership state or
  remove newer secrets — a replayed older capability is a no-op, not a
  rollback. Knowledge and key material are distinct: learning epoch N+1's
  transition does not mean holding epoch N+1 secrets until the capability
  arrives.
- Admission is explicit and additive; delivery rides the Nostr mailbox, so
  the new device need not be online.

## Device removal and rotation (decided semantics)

- **Removal** is a signed membership transition (`status = revoked`) by the
  owner, which **creates a new epoch**: remaining members receive new
  wrapped capabilities (new epoch secret → new manifest keys / object key
  base). The removed device's capability stops being honored, and future
  snapshots and objects are unreadable to it.
- **Cached plaintext already on the removed device stays readable to that
  device.** Revocation bounds future knowledge, not past possession — and
  the *epoch* model makes the boundary exact: everything under epochs the
  device held is readable; nothing after is.
- **No re-encryption of history.** If excluding remaining members from
  old-epoch content is ever wanted, that is an explicit, separate migration
  (re-encrypt + new manifests), never an implicit side effect.
- **Who may rotate when the owner is offline** is an authorization-policy
  question over the owner set (`1-of-2 may add`, `2-of-2 to remove an
  owner`, …) rather than a new key system. v0 ships exactly one owner.

## Recovery (reserved design, post-v0 implementation)

Without the root key, ciphertext is unrecoverable once every device holding
capabilities is lost — so recovery **is** root-key custody. The design
reserved for it (deferred with the Shamir decision, but the design space is
held open now):

- **Guardians ("emergency contacts")**: a set of Nostr pubkeys recorded as
  first-class state in the membership log. Guardians hold Shamir shares of
  the root key, **k-of-n required to reconstruct**; shares are delivered and
  stored as opaque blobs via the encrypted Nostr mailbox — guardians learn
  only "I hold a share for drive X", never Wyrd contents or membership.
- **Reconstruction flow**: k guardians return their shares → an owner device
  reconstructs the root key → mints a fresh capability / new epoch. Compromised
  or lost guardians are handled by rotating the shares (re-split, re-deliver).
- **Web of trust's role is vetting, not crypto**: Nostr social conventions
  (web of trust, NIP-05) help verify *that a guardian pubkey is the person
  you think it is*. The threshold scheme carries the actual security.
- Implementation is post-v0; the membership-log fields for the guardian set
  are reserved so adding recovery later does not change the epoch model.

## NIP-46 remote signing (optional, scoped, default-deny)

The daemon may delegate identity operations to a remote signer (hardware,
phone, bunker) over NIP-46, and must never receive the nsec:

```
Wyrd daemon ── "sign this snapshot" ──▶ scoped signer session ──▶ signature
```

Scoping rules: the Wyrd signer session exposes `get_public_key` and
`sign_event` restricted to Wyrd event kinds only. No `nip44_decrypt`,
no arbitrary event signing, unless a concrete feature demands it —
**default-deny**. This is especially desirable when the daemon runs as a
privileged system service.

## What each party can know (the security boundary, stated precisely)

| Party | Can know | Cannot know |
|---|---|---|
| vault | Storage IDs, ciphertext sizes, counts, timing, traffic patterns | plaintext, paths, structure, **cryptographic equality of plaintexts** (fresh nonces make ciphertext equality meaningless) |
| public relay | pubkeys that choose to be publicly visible; opaque encrypted control messages | membership graphs, invitation flow, any Wyrd payload |
| drive member | full plaintext world of its epochs, all Content IDs, cross-device equality via manifests | other epochs' material it never held |
| removed device | plaintext it cached, plus old-epoch objects it already stored | anything from later epochs |

Note the deliberate asymmetry: **Content IDs are an equality oracle to
members.** That is what makes dedup and history work, and it is why the
member/vault boundary is a security boundary, not an implementation detail.

## Decision record

| # | Decision | Rationale |
|---|---|---|
| T1 | Device identity = Nostr pubkey; Schnorr signatures; no Nostr event formats; immutable device identity | deletes a bespoke identity subsystem; Nostr answers "who", Wyrd answers "what can you decrypt" |
| T2 | Root key: random 256-bit, passphrase-*wrapped* at rest; hardware later; Shamir deferred | password changes must not touch the drive's cryptographic universe; recovery architecture ≠ storage architecture |
| T3 | Control plane: Nostr (async mailbox) + iroh (live data plane); Wyrd-defined control messages inside encrypted Nostr events | offline devices/vaults need asynchronous rendezvous; bulk never through Nostr; rendezvous must be replaceable |
| T4 | Epoch-derived keys with **fresh random epoch secrets** (never derived from the root or each other); membership change → new epoch secret → manifest/object KDFs; never re-encrypt history | exact revocation: possession of epoch N yields nothing about N+1; root possession must not imply every epoch; revocation without rewriting immutable objects |
| T5 | Snapshots commit to the **membership transition** that authorizes them (not merely an epoch number); historical validity vs current eligibility are separate predicates; superseded/stranded forks never advance state; recovery grafts content, never lineage | an epoch number says *when*, a membership-state commitment says *which authorization state*; deterministic authorization everywhere; valid-signature ≠ valid transition; bounded-fork semantics for propagation races |
| T6 | NIP-46 optional, scoped, default-deny; daemon never holds the nsec | protects identity keys from the (possibly privileged) daemon process |
| T7 | Recovery reserved: guardian set (emergency contacts) as membership-log state; Shamir k-of-n shares over the encrypted Nostr mailbox; WoT for vetting only | root-key loss is unrecoverable by crypto alone; social recovery is the deferred Shamir decision given UX; design space held open without changing the epoch model |
| T8 | DriveRootKey is owner/recovery custody only; never part of an ordinary member capability | a member holding the root could derive every future epoch; revocation would collapse |
| T9 | Capabilities wrapped under secp256k1-ECDH-derived keys (HKDF) with AAD binding `(DriveId, DeviceId, transition_id, epoch)`, installed **monotonically**; revocation bounds acquisition, not possession | AAD binding alone is not recipient authentication — the ECDH-wrapped AEAD is; capabilities cannot be transplanted or replayed across drives/epochs/devices; older-capability replay is a no-op |
| T10 | Signatures are BIP-340 with **deterministic nonces** over a defined signing preimage (ASCII domain tag ‖ raw 32-byte DriveId ‖ self-delimiting preimage: counted vectors, fixed-width fields), tagged-hash challenge, full key validation (`lift_x`, 64-byte signatures); ids derive over preimage ‖ signature | BIP-340 is byte-exact, so the spec must be too; deterministic nonces make ids stable; a dedicated preimage avoids envelope-parse ambiguity |
| T11 | Cryptographic substrate: reuse audited Nostr/secp256k1 ecosystem implementations (BIP-340, ECDH, HKDF, AEAD, CSPRNG); NIP-44 for control-plane transport; NIP-04 rejected; Wyrd owns serialization, authorization semantics, and the key hierarchy | never roll your own crypto; the security budget goes to the state machine and key lifecycle, not the elliptic curve |

## Open questions

1. ~~**Membership/epoch state machine**~~ — resolved: normative in
   `epochs.md` (membership-state binding, transition authorization against
   the pre-transition owner set, conflict resolution by extension).
2. Manifest partition encoding details (sharding, chunked transfer).
3. Live-view conflict naming (e.g. by author id / snapshot timestamp).
4. Gossip message framing for snapshot announcements.
5. Chunk-size parameters (benchmark before the v1 freeze).
6. ~~Keystore KDF~~ — v0 choice recorded: **Argon2id**, 64 MiB memory,
   t=3, p=1, 16-byte random salt, 32-byte output, selected for
   portability — a compatibility choice, not a claim of optimality against
   contemporary hardware (RFC 9106's 64 MiB recommendation uses p=4).
   The derived key wraps the root key with a domain-separated AEAD; exact
   AEAD instantiation and serialization land with the keystore
   implementation. OS secure-storage integration remains open.
7. Guardian share lifecycle details (re-split procedure, share expiry,
   guardian-offline handling) — blocked behind the post-v0 recovery
   implementation.
