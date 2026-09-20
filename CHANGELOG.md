# Changelog

All notable changes to Wyrd are documented here, following [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/). `ngit release publish`
extracts release notes from the level-two section matching the release
version, so each release renames `[Unreleased]` below to its version.

## Compatibility first

The number that decides whether two builds interoperate is the **on-disk
format version**, not the app version. Every envelope carries it
(`wyrd_format::envelope::VERSION`, currently `0x00` = v0); a build rejects
envelopes it does not understand, and old envelopes are migrated at rest by
future format versions, never decoded in place. Until 1.0, assume **every**
alpha can change the format, the trust protocol, and the CLI: drives created
by one alpha may not open under the next, and the release notes for each
version say exactly what changed.

## [0.1.0-alpha.1]

### Added

- Local drive lifecycle in the `wyrd` binary: `wyrd init` creates identity,
  root custody, and genesis membership; `wyrd mount` serves a live
  read-write projection with clean shutdown on SIGINT/SIGTERM.
- Mounted write path: daemon-owned mutation queue, namespace operations,
  and append-handle semantics behind the FUSE mount.
- Demand-driven fetch: opening non-local content registers a want and
  blocks bounded (`EIO` on expiry), with read-side chunk demand and a
  real-iroh serving endpoint answering peer fetches by transport root.
- Encrypted control plane: NIP-44 mailbox sealing with a durable
  seen-event-id dedupe log, supervised live NIP-59 relay mailbox, and
  per-pass route publication into the fetch plane.
- Typed-error convention across daemon and sync boundaries (one
  `thiserror` enum per module; fail-closed authorization with
  restore-then-report recovery), documented in
  `docs/error-conventions.md`.
- Nix flake distribution: `packages.wyrd` / `apps.wyrd` (`nix build .#wyrd`,
  `nix run .#wyrd -- --help`) built from the committed `Cargo.lock` with the
  toolchain pinned in `rust-toolchain.toml`, for `aarch64-darwin`,
  `aarch64-linux`, and `x86_64-linux`. `devenv.nix` stays the development
  environment; the flake is distribution only.
- Deterministic per-platform release archives: `packages.wyrd-dist`
  (`nix build .#wyrd-dist`) produces the `wyrd-{version}-{platform}.tar.gz`
  named in `.ngit/release.yaml`, so a main release always covers every
  application platform.
- `nix` CI gate (`.ngit/act/workflows/workflow.yml`): `nix flake check` on push to
  `master` and on `ready_for_review` for PRs touching the flake, the Rust
  workspace, or the workflow itself.
- Release manifest (`.ngit/release.yaml`): per-platform `wyrd-{version}`
  archives for ngit releases, with notes extracted from this changelog.
