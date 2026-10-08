{ pkgs, inputs, ... }:
let
  inherit (pkgs.lib) optionals;
  inherit (pkgs.stdenv.hostPlatform) isLinux isDarwin;
  unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  languages.deno.enable = true;
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

    # Marketing honesty gate: claims on page/index.html stay pinned to
    # their backing docs/ sections (page/map.json + page/map.lock.json).
    # Runs only when the page, the mapping, or the docs change.
    page-check = {
      enable = true;
      name = "page docs mapping";
      entry = "deno run --allow-read page/check.ts";
      files = "^(page/|docs/|README\\.md)";
      pass_filenames = false;
    };

    # Review helper tests: the stub suite runs when the helper, its
    # library, or the suite itself changes, so broken resolve/post
    # semantics never ship green.
    review-tests = {
      enable = true;
      name = "review helper tests";
      entry = "bash .ngit/scripts/tests/test-review.sh";
      files = "^\\.ngit/scripts/(review\\.sh|ngit\\.sh|tests/test-review\\.sh)$";
      pass_filenames = false;
    };
  };

  # Release tooling: `build` wraps `.ngit/scripts/build.sh`,
  # which builds every distribution tarball this machine can produce
  # (native, Rosetta, and remote-builder legs with host capability
  # detection). Input is pinned to the release tag in a detached
  # worktree, never the working copy.
  scripts.build.exec = "${./.ngit/scripts/build.sh} \"$@\"";

  # Review tooling: `review` wraps `.ngit/scripts/review.sh`, the
  # tested resolve/context/post helpers local PR reviews call instead
  # of re-deriving ngit ceremony. The store-installed script loses its
  # sibling ngit.sh, so REVIEW_LIB_DIR points it back at the stored
  # scripts directory. The stub-based suite runs from the checkout, not
  # exposed as a `scripts.*` command: its fixtures resolve
  # source-relative paths.
  scripts.review.exec = "REVIEW_LIB_DIR=${./.ngit/scripts} ${./.ngit/scripts/review.sh} \"$@\"";
}
