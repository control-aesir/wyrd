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
      # Product platforms. x86_64-darwin is deliberately absent even though
      # rust-toolchain.toml lists the target: no builder covers it, so it
      # ships nothing until one does.
      systems = [ "aarch64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      # ngit release platform tags, which order OS before architecture.
      ngitPlatforms = {
        aarch64-darwin = "macos-aarch64";
        aarch64-linux = "linux-aarch64";
        x86_64-linux = "linux-x86_64";
      };
      version = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).workspace.package.version;
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
          inherit version;
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
      # Deterministic release archive for one system: the tarball named in
      # .ngit/release.yaml for that system's platform tag. The release
      # procedure builds one per platform and publishes the set, so a main
      # release always covers every application platform.
      distFor = system:
        let
          pkgs = pkgsFor system;
          platform = ngitPlatforms.${system};
          dirname = "wyrd-${version}-${platform}";
        in
        pkgs.runCommand "${dirname}.tar.gz" { } ''
          mkdir -p staging/${dirname}/bin
          cp ${self.packages.${system}.wyrd}/bin/wyrd staging/${dirname}/bin/
          tar -czf $out -C staging ${dirname}
        '';
    in
    {
      packages = forAllSystems (system: {
        wyrd = wyrdFor system;
        wyrd-dist = distFor system;
        default = self.packages.${system}.wyrd;
      });
      apps = forAllSystems (system: {
        wyrd = {
          type = "app";
          program = nixpkgs.lib.getExe self.packages.${system}.wyrd;
          meta = {
            description = "Run the wyrd drive daemon (init, mount)";
          };
        };
        default = self.apps.${system}.wyrd;
      });
      # The package build plus the release archive, per system.
      # `nix flake check` builds the current system's entries; CI covers
      # linux, the maintainer's machine darwin.
      checks = forAllSystems (system: {
        wyrd = self.packages.${system}.wyrd;
        wyrd-dist = self.packages.${system}.wyrd-dist;
      });
    };
}
