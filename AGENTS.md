# AGENTS.md

Decentralized, append-only, content-addressed drive system. Pre-alpha.

Read `docs/architecture.md` first (one page), then the focused docs it links
to. The README carries the vision; `docs/` carries the current design contract.

## Layout

- `crates/wyrd-format` — CAS, typed identities, chunking, Merkle snapshot DAG. The format contract.
- `crates/wyrd-sync` — iroh transport, encrypted manifests, roles × materialization, two-phase content.
- `crates/wyrd-fuse` — FUSE mount (unimplemented; macFUSE/FUSE3 constraints).
- `docs/` — agent-digestible architecture docs. `object-model.md` is the normative
  v0 format spec; `trust.md` and `epochs.md` are the normative trust and
  authorization contracts. Keep them current when behavior changes; stale
  docs are worse than missing docs.
- `devenv.nix` / `devenv.yaml` / `rust-toolchain.toml` — dev environment.

## Hard rules

- `wyrd-format` must not gain networking, async, or FUSE dependencies.
  Allowed: blake3, hex, thiserror, fastcdc, serde (when serialization lands).
- `wyrd-format` is the plaintext world: keys, ciphertext, and manifests live
  in `wyrd-sync`. Content IDs never reach vault-visible metadata.
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
cargo check        # workspace build/validation
cargo test         # once there are tests
devenv shell       # enter the dev environment (rust, git-hooks)
```

## Conventions

- Conventional Commits. Nothing commits to `master` directly; use `pr/<name>`
  branches (see the ngit skill).
- Comments explain how code is used, not what it does line-by-line. Keep them
  in sync with the code.
