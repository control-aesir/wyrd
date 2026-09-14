{
  description = "Wyrd: decentralized, append-only, content-addressed drive system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    crane.url = "github:ipetkov/crane";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, crane, rust-overlay, ... }:
    let
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
      wyrdFor = system:
        let
          pkgs = pkgsFor system;
          inherit (pkgs) lib stdenv;
          # The exact channel pinned in ./rust-toolchain.toml, so the flake
          # build compiles with the same rustc as the devenv shell.
          toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;
        in
        craneLib.buildPackage {
          pname = "wyrd";
          version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
          # The workspace exactly as Cargo sees it, from the committed
          # Cargo.lock; target/ and VCS state never enter the build.
          src = craneLib.cleanCargoSource ./.;
          # Only the user-facing binary. Library crates ride along as its
          # dependencies; nothing else installs a binary.
          cargoExtraArgs = "-p wyrd-daemon";
          strictDeps = true;
          # The test suite (nextest, doctests) runs in rust-ci with the full
          # dev environment; the distribution build only proves the binary
          # compiles and links, including inside the Linux sandbox.
          doCheck = false;
          nativeBuildInputs = [ pkgs.pkg-config ];
          # System libraries probed by build scripts (fuser's pkg-config
          # probe) belong in buildInputs, not nativeBuildInputs: under
          # strictDeps the pkg-config role hook only exposes host-offset
          # deps on the unsuffixed PKG_CONFIG_PATH the probe reads.
          buildInputs = lib.optionals stdenv.isDarwin [
            # Build-time headers/stubs for fuser's libfuse2 probe. Mounting
            # at runtime still needs system macFUSE, which nix cannot
            # provide; same split as devenv.nix.
            pkgs.macfuse-stubs
          ] ++ lib.optionals stdenv.isLinux [
            # libfuse2 headers for fuser's link probe.
            pkgs.fuse
          ];
          meta = with lib; {
            description = "Decentralized, append-only, content-addressed drive system (alpha)";
            homepage = "https://gitworkshop.dev";
            license = licenses.mit;
            platforms = systems;
            mainProgram = "wyrd";
          };
        };
    in
    {
      packages = forAllSystems (system: {
        wyrd = wyrdFor system;
        default = self.packages.${system}.wyrd;
      });
      apps = forAllSystems (system: {
        wyrd = {
          type = "app";
          program = nixpkgs.lib.getExe self.packages.${system}.wyrd;
        };
        default = self.apps.${system}.wyrd;
      });
      # The package build, per system. `nix flake check` builds the current
      # system's entry; CI covers linux, the maintainer's machine darwin.
      checks = forAllSystems (system: {
        wyrd = self.packages.${system}.wyrd;
      });
    };
}
