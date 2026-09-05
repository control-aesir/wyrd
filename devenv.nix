{ config, pkgs, inputs, ... }:
let
  inherit (pkgs.lib) optionals;
  inherit (pkgs.stdenv.hostPlatform) isDarwin isLinux;
  unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  languages.rust.enable = true;
  languages.rust.toolchainFile = ./rust-toolchain.toml;

  packages = with unstable; [
    pkg-config
  ] ++ optionals isLinux [
    # Fast parallel linker for large debug artifacts. Only wired up when we
    # add .cargo/config.toml with -fuse-ld=mold; falls back to the system
    # linker without it.
    mold
  ];

  # Native FUSE for wyrd-fuse development stays out of nix on darwin:
  # macFUSE is a system installation with kernel-extension expectations.
  # Revisit if/when we target FUSE 3 on Linux.

  git-hooks.hooks = {
    clippy.enable = true;
    rustfmt.enable = true;
    nixpkgs-fmt.enable = true;
    commitizen.enable = true;
    typos.enable = true;
  };
}
