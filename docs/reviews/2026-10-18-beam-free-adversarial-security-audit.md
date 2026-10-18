# Wyrd Adversarial Security Audit

Reviewer: OpenCode agent (model: `beam-free`, model id `opencode-go/beam-free`)
Tree reviewed: `master` @ `c78502d15e863de517c1e0a18182668ba173cf9f`
(2026-10-18). Working tree: `devenv.lock` modified (4 insertions, 4 deletions);
no source files modified. This review creates only this file.

## A. Executive assessment

Wyrd's cryptographic, membership, durable-state, and crate-boundary foundations
are unusually well-defended for pre-alpha software: content identity is
domain-separated BLAKE3, snapshots are BIP-340 signed and drive-bound, epoch
secrets are fresh random per transition, capabilities are ECDH-wrapped and
authorized against the transition's produced state, objects are AEAD-bound to
their ContentId, the durable log is hash-chained with CURRENT, and resource
ceilings exist at every major intake surface. The crate DAG and the single
`from_verified_unchecked` crossing are machine-enforced by contract 34.

This audit did not confirm any exploitable vulnerability in the inspected
code paths. The residual risk is concentrated in three areas that are
documented as incomplete rather than broken: (1) feature-unification can
silently enable the test-only `insecure-fast-kdf` profile in aggregate builds;
(2) several OS-level durability and local-user assumptions (directory
ownership, symlink handling on drive paths) rely on cooperative callers and
are not hardened against a hostile local user pre-creating paths; and
(3) the live multi-member and mixed-version paths remain partially unproven
by the contract suite (ignored upgrade invariants). None of these was
demonstrated to be exploitable as a remote or authenticated-peer attack.

I did not run the slow-profile or live-relay suites, the Lima/microVM e2e
harness, or any fuzzer. Conclusions about those surfaces are static only.

## B. Confirmed vulnerabilities

None confirmed. No behavior in the inspected code was established to violate
a security property with a credible attack or failure path under the stated
threat model. In particular, no primitive-level cryptographic bypass, no
remote resource-exhaustion path past the documented ceilings, and no
authorization bypass in the membership/capability state machine was found
in the code actually exercised.

## C. Probable vulnerabilities and unverified hypotheses

1. **Feature-unification KDF weakening (probable, operator-build only).**
   - Location: `crates/wyrd-sync/Cargo.toml` (`insecure-fast-kdf`), consumed
     by `crates/wyrd-core`, `wyrd-daemon`, `wyrd-cli`, `wyrd-contracts`,
     `wyrd-embed` as dev-dependencies.
   - Concern: a workspace build with `--all-features` (or any downstream
     that enables the feature transitively) unifies the feature across the
     graph and compiles `wyrd-sync`'s keystore with the 8 KiB / 1-pass
     Argon2id profile even in release artifacts. The pinning tests
     (`kdf_parameters_are_pinned`, `prod_kdf_params_round_trip`) guard the
     constants but do not guard which profile a given artifact actually links.
   - Missing evidence: whether any supported release pipeline invokes
     `--all-features`; the feature is documented as test-only.
   - Next action: make the profile selection impossible to enable outside
     `cfg(test)` (e.g. remove the feature and use `cfg(test)` exclusively),
     or add a build-time assertion that the production profile is linked.

2. **Drive-directory pre-creation by a local user (unverified hypothesis).**
   - Location: `crates/wyrd-sync/src/durable/store.rs` (`ensure_owner_only_dir`,
     `restrict_dir_owner_only`), `crates/wyrd-cli/src/credentials.rs`.
   - Concern: `ensure_owner_only_dir` returns Ok without changing mode when
     the path already exists as a directory. Fresh-drive restriction to
     0o700 only happens on the missing-`DRIVE` path inside `DurableStore::open`.
     A local user who can create the drive directory (and, for a member
     drive, plant a `DRIVE` file) before the victim opens it may be able to
     keep a loose mode or cause a `DriveMismatch` refusal (DoS). The
     credential-file path already uses `O_NOFOLLOW` and fstat checks; the
     drive-directory path does not.
   - Missing evidence: whether the deployment model allows an attacker to
     pre-create the drive directory with the victim's intended path and
     permissions; typical drive dirs are created by the owner.
   - Next action: either document the trusted-directory assumption
     explicitly, or harden `ensure_owner_only_dir` to verify ownership and
     mode of pre-existing directories and refuse foreign-owned ones.

3. **Ignored upgrade invariants (unverified hypothesis, availability only).**
   - Location: `wyrd-contracts` (two `#[ignore]`d tests with `todo!()` bodies
     for invariants 2 and 5).
   - Concern: mixed-version and payload-replay compatibility is unproven, so
     a future version could silently break readability. Not a
     confidentiality/integrity issue for a single version.
   - Next action: implement the two contract bodies before any release that
     claims upgrade support.

## D. Hardening recommendations

- Pin the production KDF profile at link time rather than by convention
  (see C.1). Highest priority among hardening items.
- Add an ownership/mode check to `ensure_owner_only_dir` for pre-existing
  directories, mirroring `read_secret_file`'s fstat discipline, or document
  the trusted-parent-directory assumption in `docs/cli.md`.
- Make the mailbox's outer wire limit (`MAX_MAILBOX_RELAY_WIRE_BYTES`) and
  the SDK `RelayLimits` configuration a single named constant shared with
  the intake layer, so a future edit cannot drift them apart.
- Consider a default (non-`None`) retained-bytes quota or a documented
  operator-settable one; the append-only store has no GC, so unbounded
  retention is a disk-exhaustion vector for any peer able to push content.
- Add a fuzz target for `Manifest::from_canonical_bytes`,
  `MembershipTransition::from_canonical_bytes`, and `Envelope::decode` even
  though decoders already use `min(4096)` pre-allocation; the count checks
  run after decode.

## E. Invariant and attack-surface coverage

| Area | Status | Evidence |
|---|---|---|
| A. Resource exhaustion / bounded work | Partially inspected | Intake limits (`ingest.rs`), mailbox sizes (`mailbox/mod.rs`), want registry (`want.rs`), budgets (`budgets.rs`); not inspected: serving mirror, bulk transfer framing, every handle type under load |
| B. Cryptographic / identity invariants | Inspected (static) | `seal.rs`, `keys/*`, `signing.rs`, `authorization/predicates.rs`; no runtime crypto verification performed |
| C. Authorization / protocol state machines | Inspected (static) | `membership/*`, `capability/model.rs`, `runtime/intake/mod.rs`; not executed against hostile peers |
| D. Persistence / crashes / recovery | Inspected (static) | `durable/*`, `crash-consistency.md`; no crash injection performed in this audit |
| E. Filesystem / OS boundaries | Partially inspected | `credentials.rs`, `fs_store.rs`, `durable/store.rs`; FUSE write path read but not fuzzed |
| F. Secrets / config / deployment | Inspected (static) | `credentials.rs`, `drive_config.rs`, `update/*`; logs/diagnostics not audited for secret leakage |
| G. Cross-crate composition | Inspected (static) | `layer_contracts.rs` read; contract suite not re-run for this audit |
| Entry points examined | `wyrd` CLI, `Engine::create`/`open_keystore`, mailbox intake, FUSE backend, serving vault/bulk, durable store | |
| Entry points not examined | NIP-46 signer client (unimplemented), mobile backends, Lima/microVM e2e, update self-swap runtime, vendor fuser | |

## F. Validation and blind spots

Commands actually run:
- `cargo check` (workspace) — passed (5.8s).
- `cargo nextest run -p wyrd-sync` — 932 passed, 4 skipped.
- `cargo deny check` — advisories, bans, licenses, sources all ok.

Not run: full workspace nextest, clippy, doctests, slow profile, fuzzers, e2e.
Reproducer status: none created (no confirmed vulnerability to reproduce).
Tests providing meaningful security evidence: `kdf_parameters_are_pinned`,
`prod_kdf_params_round_trip`, `malformed_seals_are_rejected`,
`verify_enforces_the_whole_entry`, `error_rendering_does_not_stringify_content_ids`,
`mailbox::tests_mailbox` oversize cases, `tests_permissions` custody modes.

## G. Remediation order

Block before next release: implement the two ignored upgrade-invariant
contract bodies if upgrade support is claimed; resolve the
`insecure-fast-kdf` feature-unification footgun.

Follow-up hardening: drive-directory ownership/mode hardening; retained-bytes
default quota; fuzz targets for canonical decoders; shared wire-limit
constant between mailbox and intake.

---

No production source was changed as part of this audit.
