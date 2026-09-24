# Capability and message binding matrix

Review artifact for the recipient/key-substitution audit: one row per
object and message that carries secrets or authority, stating what
authenticates it, what context it is bound to, and the transplant
question — can valid material from context A move into context B?
Linked from `trust.md` (AEAD binding); the constructions it names are
pinned there.

The five-value rule: every capability path binds
`DriveId / DeviceId / EncryptionKey / TransitionId / Epoch` together,
and the encryption key in use is always the one authenticated by the
canonical membership transition being acted upon, never a key supplied
alongside the message. The table proves the rule row by row.

## Capability wrap (inner)

- Authenticates: ECDH to the recipient's registered encryption key
  plus AEAD over
  `domain ‖ drive ‖ device ‖ enc_key ‖ transition ‖ epoch`; the
  plaintext repeats all five plus the secret count, and unwrap
  enforces header↔plaintext agreement and `proven_pk == claimed key`.
- Transplant: any field altered fails the tag; a wrap for another
  device does not open under this device's secret at all.
- Recipient provenance: `Capability::mint` reads the key from the
  transition's own derived state — forgery is unrepresentable. The
  only production `Capability::new` with a caller-supplied key is the
  genesis self-capability, which authorizes against the log before
  anything commits.
- Pinned by: header-tamper cases, wrong-drive/wrong-device install
  refusal, stale-key refusal (`keys/capability/tests.rs`); foreign
  wrap suppresses at intake without installing
  (`tests_capability::capability_minted_for_another_device_never_installs`).

## CapabilityPayload outer (device, epoch)

- Authenticates: nothing — carried delivery metadata, sealed only by
  the epoch control envelope around it.
- Transplant: intake cross-checks both fields against the unwrapped
  capability and suppresses on disagreement, so an outer lie never
  steers installation.
- Pinned by: outer device-lie and outer epoch-lie suppression
  (`tests_capability.rs`).

## RotationDelivery outer

- Authenticates: AEAD over
  `domain ‖ version ‖ drive ‖ recipient ‖ enc_key ‖ epoch`, plaintext
  repeating drive/device/epoch/transition/wrapped/owner-proof,
  inner↔outer agreement, a sender-is-member-of-the-authorizing-state
  check, and an owner proof over a digest of the unwrapped secret
  vector whose signer must be an owner of the transition's
  *predecessor* state. The two are separate authorities: the sender
  check grants delivery, the proof grants mint.
- Transplant: inner≠outer device or epoch suppresses; a genuine wrap
  paired with a substituted same-epoch transition suppresses at the
  transition↔capability binding check; a non-member sender's delivery
  never commits.
- Recipient provenance: the wrap key comes from chain state
  (`encryption_key_of` on the authorizing transition), documented in
  code as chain-state-never-caller.
- Issuer provenance: a member that mints its own vector cannot produce
  the owner's proof, so its delivery is refused without changing the
  keyring; the outgoing owner of a handover can, because authority is
  the pre-state, while the incoming owner cannot.
- Pinned by: inner/outer mismatch, non-member sender, removed-sender,
  and substituted-transition suppression (`tests_rotation.rs`), plus
  member-minted and non-owner-signed refusal, handover authorization,
  and the inverse incoming-owner refusal.

## SealedBootstrap (invitation)

- Authenticates: ECDH to the invitee's encryption key, AAD binding
  the recipient and key, the owner's signature over the unsigned
  bytes, and `verify_invitation` (invitee/device/drive/key equality
  plus authoritative-genesis validation) before anything touches disk.
- Transplant: a seal to a substituted key does not open under the
  victim's secret; a seal for another device fails the invitee check
  after opening; a foreign drive fails the drive check; an invalid
  genesis fails closed before disk.
- Pinned by: another-device refusal, invalid-genesis refusal,
  foreign-capability refusal, substituted-key refusal
  (`bootstrap.rs` accept-invitation tests).

## EscrowRecord

- Authenticates: AEAD under the root-derived per-epoch escrow key,
  AAD `version ‖ DriveId ‖ epoch`.
- Transplant: wrong root, drive, or epoch fails the tag; recovery
  needs the right root *and* the right record.
- Pinned by: root/drive/epoch binding tests (`keys/escrow.rs`
  tests).

## SealedControl envelope

- Authenticates: the epoch control key, AAD
  `version ‖ drive ‖ kind ‖ epoch`, inner header agreement, and
  payload↔envelope epoch agreement for epoch-repeating payloads.
- Transplant: a capability or announcement sealed at the wrong epoch
  fails `HeaderMismatch` at open; the suppression id covers the
  sealed bytes, so a remembered verdict applies without re-opening.
- Pinned by: seal/open round-trip and epoch-agreement tests, wrong-key
  refusal, suppression-before-open precedence (`control/mod.rs`
  tests).

## SnapshotAnnouncement

- Authenticates: drive-bound BIP-340 author signature, membership
  binding to a known transition, epoch agreement with that
  transition, and canonicality at commit.
- Transplant: bad signature suppresses; unknown transition defers
  (cheaply, before verification); epoch mismatch suppresses;
  non-canonical history defers or suppresses by status.
- Pinned by: defer/suppress/verify-order tests
  (`tests_announcement.rs`, including
  `unsigned_announcement_for_unseen_transition_defers_then_suppresses`).

## MembershipTransition

- Authenticates: drive-bound BIP-340 author signature, derived-roots
  rule, pre-transition owner authority, and the chain rules
  (single-use identity, retirement, conflict freeze, exact
  resolutions).
- Transplant: a fork contests and voids; a re-admit of a retired
  identity is invalid; an orphan pends.
- Pinned by: the membership conformance suite.

## Durable Fact::Capability

- Authenticates: the single `AuthorizedCapability::authorize` gate
  before commit; replay re-authorizes every record against the
  current log instead of trusting the bytes.
- Transplant: non-member, foreign-transition, short-epoch, unknown,
  and foreign-drive capabilities fail the commit; sealed epoch
  mismatches fail closed.
- Pinned by: durable commit-gate tests (`durable/tests.rs`).
