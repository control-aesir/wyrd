# AGENTS.md

Decentralized, append-only, content-addressed drive system. Pre-alpha.

Read `docs/architecture.md` first (one page), then the focused docs it links
to. The README carries the vision; `docs/` carries the current design contract.

## Layout

- `crates/wyrd-format` — CAS, typed identities, chunking, Merkle snapshot DAG. The format contract.
- `crates/wyrd-sync` — iroh transport, encrypted manifests, roles × materialization, two-phase content.
- `crates/wyrd-fuse` — Mount-free drive view (the filesystem-shaped read surface; never mounts).
- `crates/wyrd-core` — Embeddable local node (namespace, mutations, materialization, sync control). Depends on `wyrd-format`/`wyrd-sync` only; the daemon is one host for it.
- `crates/wyrd-daemon` — Composition library: engine + view + presentation backends (FUSE adapter today; mobile file surfaces later). The composer per T16.
- `crates/wyrd-cli` — The `wyrd` process host (binary-only): argument parsing, credential files, mount orchestration, diagnostics, exit codes over the daemon's public surface.
- `crates/wyrd-contracts` — Cross-crate architectural contract suite: one named test per review contract, composed end to end over the public APIs. Workspace leaf over the library crates (it cannot depend on the binary-only `wyrd-cli`; the CLI's edges are pinned by contract 34's member-wide check instead), nothing depends on it.
- `docs/` — agent-digestible architecture docs. `object-model.md` is the normative
  v0 format spec; `trust.md` and `epochs.md` are the normative trust and
  authorization contracts. Keep them current when behavior changes; stale
  docs are worse than missing docs.
- `devenv.nix` / `devenv.yaml` / `rust-toolchain.toml` — dev environment.

## Hard rules

- `wyrd-format` must not gain networking, async, or FUSE dependencies.
  Allowed: blake3, hex, thiserror, fastcdc, serde (when serialization lands).
- `wyrd-format` is the plaintext world: keys and ciphertext live in
  `wyrd-sync`. Manifests split across the two: schema and canonical
  plaintext representation belong to `wyrd-format`; manifest encryption,
  storage addressing, and capability semantics belong to `wyrd-sync`.
  Content IDs never reach vault-visible metadata.
- Objects are immutable; never mutate stored content in place; `put` of
  existing content is a no-op. GC does not exist — the store is
  append-only indefinitely in v0.
- Snapshots are never rewritten (the DAG is append-only). Snapshots are
  signed with the author's Nostr identity key, bound to the DriveId and to
  the membership transition that authorizes them. Nostr supplies identity
  and signatures only — never Nostr event formats, no social-Nostr
  requirements, and membership state is always encrypted.
- Device identity is a Nostr public key and is immutable: rotating a Nostr
  key means removing the old device membership and admitting the new key.
- Crypto and sync-layer implementation is unlocked. Implementation must
  follow `docs/trust.md` and `docs/epochs.md` as normative contracts: root
  custody, fresh random epoch secrets, the membership state machine, and the
  Nostr/iroh control-plane split are decided; do not relitigate them.
- Never implement cryptographic primitives (secp256k1, BIP-340, ECDH, HKDF,
  AEAD, CSPRNG). Use audited crates from the nostr/secp256k1 ecosystem; see
  the Cryptographic substrate section of `docs/trust.md` (decision T11).
- iroh dependency versions change as a set.
- Format decisions live in the decision record at the bottom of
  `docs/object-model.md`. Remaining open questions there are decisions to be
  made, not assumptions to be coded around. Do not code past them silently.

## Commands

```
devenv shell -- cargo check                 # workspace build/validation
devenv shell -- cargo nextest run           # workspace tests (unit + integration)
devenv shell -- cargo test --workspace --doc  # doctests; nextest skips these
devenv shell -- cargo nextest run --profile slow
                                            # >10s live-relay tests; excluded from
                                            # regular runs, gated on master CI
devenv shell -- cargo test -p wyrd-cli      # CLI suite (argument parsing, exit codes)
devenv shell                # enter the dev environment (rust, git-hooks)
```

## Running the Lima e2e suite

`./lima/run-alpha.sh [--keep] [--step N[,N...]]` is long (minutes) and lives in a
guest. Operate it, never babysit it blind:

- **Never pipe it through `tail`.** A foreground pipe buffers everything, so
  a twenty-minute run looks like a hang. Run it detached with the output to a
  log (`(./lima/run-alpha.sh --keep > /tmp/lima/run.log 2>&1 &)`) and poll the
  log in bounded chunks (~8 minutes per poll so the session never times out).
- `--step` takes a comma list and runs the prefix closure (steps build on
  each other): `--step 4` runs steps 1–4, `--step 4,6` runs 1–6. An empty
  entry or a non-step is refused; an empty value means all steps.
- **A repeated `FAIL:` line is a stop, not patience.** The harness exits on
  the first failed check, so two identical polls mean the run is over —
  read the log, pull the failing mount's stderr out of the guest
  (`limactl shell wyrd-alpha -- grep ... "/tmp/wyrd-e2e/logs/mount-*.err"`), fix,
  rerun. Ten identical polls have happened; none were productive.
- **Check liveness where it lives:** the guest contract process
  (`limactl shell wyrd-alpha -- pgrep -f alpha-lima.sh`). A host `pgrep` for
  the wrapper matches short-lived subshells and lies about liveness.
- `limactl shell` prints a harmless `cd: <host path>: No such file` when the
  host cwd does not exist in the guest. It is noise; the command still runs.
- Any background process the harness starts (mounts, the relay) inherits its
  stdout, so a `die` that leaves one running makes the host wrapper wait on a
  pipe that never closes. The harness reaps them in an EXIT trap; keep it that
  way when adding steps.
- The guest's drive state is under `/tmp/wyrd-e2e` (guest-local disk, never
  the 9p share: FUSE mountpoints and drive dirs over 9p are unsupported);
  logs per run in `/tmp/wyrd-e2e/logs`.
- Failures here are usually product bugs, not harness bugs — the suite exists
  to find them. Diagnose from the phase timings in the mount logs
  (`wyrd_core=debug` is on for step 6) before touching the script.

## Conventions

- Conventional Commits. Nothing commits to `master` directly; use `pr/<name>`
  branches (see the ngit skill).
- Follow `docs/collaboration-workflow.md` for issue triage, PR review, merge,
  and issue resolution. Project labels are applied after issue creation:
  exactly one type (`bug`, `enhancement`, or `chore`), one priority (`P0` to
  `P4`), and one `release:*` milestone.
- Comments explain how code is used, not what it does line-by-line. Keep them
  in sync with the code.
- Run outside an active devenv with `devenv shell -- ...`; bare commands 
  assume you are already inside `devenv shell`.
