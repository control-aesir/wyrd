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

  # Release tooling: `build` wraps `.ngit/scripts/build.sh`,
  # which builds every distribution tarball this machine can produce
  # (native, Rosetta, and remote-builder legs with host capability
  # detection). Input is pinned to the release tag in a detached
  # worktree, never the working copy.
  scripts.build.exec = "${./.ngit/scripts/build.sh} \"$@\"";
}
