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

## [Unreleased]

### Added

- Nix flake distribution: `packages.wyrd` / `apps.wyrd` (`nix build .#wyrd`,
  `nix run .#wyrd -- --help`) built from the committed `Cargo.lock` with the
  toolchain pinned in `rust-toolchain.toml`, for `aarch64-darwin`,
  `aarch64-linux`, and `x86_64-linux`. `devenv.nix` stays the development
  environment; the flake is distribution only.
- Deterministic per-platform release archives: `packages.wyrd-dist`
  (`nix build .#wyrd-dist`) produces the `wyrd-{version}-{platform}.tar.gz`
  named in `.ngit/release.yaml`, so a main release always covers every
  application platform.
- `nix` CI gate (`.ngit/act/workflows/nix.yml`): `nix flake check` on push to
  `master` and on `ready_for_review` for PRs touching the flake, the Rust
  workspace, or the workflow itself.
- Release manifest (`.ngit/release.yaml`): per-platform `wyrd-{version}`
  archives for ngit releases, with notes extracted from this changelog.
