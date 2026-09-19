{ pkgs, inputs, ... }:
let
  inherit (pkgs.lib) optionals;
  inherit (pkgs.stdenv.hostPlatform) isLinux isDarwin;
  unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  dotenv.enable = true;

  languages.rust.enable = true;
  languages.rust.toolchainFile = ./rust-toolchain.toml;

  packages = with unstable; [
    cargo-audit
    cargo-deny
    cargo-nextest
    pkg-config
  ] ++ optionals isLinux [
    # Fast parallel linker for large debug artifacts. Only wired up when we
    # add .cargo/config.toml with -fuse-ld=mold; falls back to the system
    # linker without it.
    mold
  ] ++ optionals isDarwin [
    # Build-time headers/stubs for fuser's libfuse probes (fuse.pc from
    # nixpkgs, fuse3.pc from our own stubs: nix/macfuse3-stubs.nix).
    macfuse-stubs
    (pkgs.callPackage ./nix/macfuse3-stubs.nix { })
  ];

  # FUSE on darwin is a build/runtime split: the stubs above only cover
  # compiling and linking (headers + fuse.pc/fuse3.pc; devenv wires
  # PKG_CONFIG_PATH to their pkgconfig dirs automatically, so the manual
  # `export PKG_CONFIG_PATH=...` from fuser's README for `nix-env`
  # installs is not needed here). Mounting at runtime still needs the
  # real system macFUSE (kernel extension,
  # /Library/Filesystems/macfuse.fs), which nix cannot provide.
  # Revisit if/when we target FUSE 3 on Linux.

  git-hooks.hooks = {
    clippy.enable = true;
    rustfmt.enable = true;
    nixpkgs-fmt.enable = true;
    commitizen.enable = true;
    typos.enable = true;

    # Dependency-policy gates run on push, not on commit: `cargo audit`
    # fetches the advisory database over the network, and both checks scan
    # the whole lockfile. Policy itself lives in deny.toml; CI enforces the
    # same checks so a push without hooks installed is still caught.
    cargo-audit = {
      enable = true;
      entry = "cargo audit";
      stages = [ "push" ];
      pass_filenames = false;
    };
    cargo-deny = {
      enable = true;
      entry = "cargo deny check";
      stages = [ "push" ];
      pass_filenames = false;
    };
  };

  # Release tooling: build the Linux distribution tarballs from a Mac.
  # The flake builds natively per system, so `nix build .#wyrd-dist` on
  # darwin only yields macos-aarch64. This wraps one containerized native
  # build per Linux target (amd64 runs under Docker Desktop Rosetta
  # emulation: slower, but it only has to succeed once per release).
  # Input is pinned to the release tag via `git archive`, never the
  # working copy, so a dirty tree cannot bake into a release tarball.
  # The builder image is pinned by digest (multi-arch manifest: docker
  # resolves the right arch per --platform). Refresh it with
  # `docker buildx imagetools inspect nixos/nix:latest` (or the Hub tag
  # API) and record the new digest here; never float on `:latest`.
  scripts.build-linux-dist.exec = ''
    set -euo pipefail
    VERSION="''${1:?usage: build-linux-dist <version> (e.g. 0.1.0-alpha.1)}"
    TAG="v$VERSION"
    NIX_IMAGE="nixos/nix@sha256:7a007c766426c1877758ddc5cb87a965ac131fc78c582ce0083d922d51ae945c"
    git rev-parse --verify --quiet "$TAG" >/dev/null \
      || { echo "tag $TAG does not exist" >&2; exit 1; }
    command -v docker >/dev/null \
      || { echo "docker is required (Docker Desktop with Rosetta enabled for amd64)" >&2; exit 1; }
    ROOT=$(git rev-parse --show-toplevel)
    EXPORT=$(mktemp -d)
    trap 'rm -rf "$EXPORT"' EXIT
    git archive "$TAG" | tar -x -C "$EXPORT"
    mkdir -p "$ROOT/dist"
    # A named volume persists the container Nix store across runs: the
    # store is content-addressed, so a retry or a second target reuses
    # identical derivations instead of recompiling the world.
    docker volume create wyrd-nix-store >/dev/null
    for TARGET in linux/arm64 linux/amd64; do
      echo "building $TARGET from $TAG..."
      # Address the package by explicit system, never the bare
      # `#wyrd-dist` attr: under Rosetta emulation nix resolved the
      # bare attr to the aarch64 output inside the amd64 container,
      # silently rebuilding one arch twice (verified by eval).
      case "$TARGET" in
        linux/arm64) SYSTEM=aarch64-linux ;;
        linux/amd64) SYSTEM=x86_64-linux ;;
      esac
      # seccomp=unconfined: Docker Desktop (and Rosetta emulation for
      # amd64) rejects the seccomp-BPF sandbox Nix installs for its
      # builds. Unconfining the container seccomp profile lets Nix
      # sandbox the build itself, which is the isolation that matters
      # for reproducible artifacts.
      docker run --rm --platform "$TARGET" --security-opt seccomp=unconfined \
        -v "$EXPORT:/src:ro" -v "$ROOT/dist:/out" -v wyrd-nix-store:/nix \
        "$NIX_IMAGE" sh -c \
          'nix --extra-experimental-features "nix-command flakes" build "/src#packages-'"''$SYSTEM"'.wyrd-dist" --out-link /tmp/wyrd-dist && cp /tmp/wyrd-dist "/out/$(basename "$(readlink /tmp/wyrd-dist)")"'
    done
    # Smoke check: release.yaml names exactly these two archives, and
    # ngit rejects partial platform coverage on the main channel.
    for ARTIFACT in "$ROOT/dist/wyrd-$VERSION-linux-x86_64.tar.gz" "$ROOT/dist/wyrd-$VERSION-linux-aarch64.tar.gz"; do
      [ -f "$ARTIFACT" ] || { echo "missing expected artifact $ARTIFACT" >&2; exit 1; }
    done
    echo "dist/:"
    ls "$ROOT/dist"
  '';
}
