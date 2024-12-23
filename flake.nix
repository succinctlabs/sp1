{
  description = "sp1";
  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    gitignore = {
      url = "github:hercules-ci/gitignore.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      flake-parts,
      rust-overlay,
      crane,
      gitignore,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [

      ];
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          craneLib = (crane.mkLib pkgs).overrideToolchain rust-toolchain;
          rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain;
          buildInputs = with pkgs; [
            openssl
            openssl.dev
            pkg-config
          ];
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = with inputs; [
              rust-overlay.overlays.default
            ];
          };
          devShells.default = pkgs.mkShell {
            buildInputs = [
              rust-toolchain
            ] ++ buildInputs;
          };
          packages =
            let
              cargoArtifacts = craneLib.buildDepsOnly {
                src = craneLib.cleanCargoSource ./.;
                doCheck = false;
                inherit buildInputs;
              };

              # do not depend on nix files and ignored, but still use bin precompiles
              nixFilter = name: type: !(pkgs.lib.hasSuffix ".nix" name);
              srcFilter =
                src:
                pkgs.lib.cleanSourceWith {
                  filter = nixFilter;
                  src = gitignore.lib.gitignoreSource src;
                };
            in
            {
              default = craneLib.buildPackage rec {
                inherit cargoArtifacts;
                pname = "cargo-prove";
                name = pname;
                doCheck = false;
                src = srcFilter ./.;
                meta = {
                  description = "cargo-prove";
                  license = pkgs.lib.licenses.mit;
                };
                cargoBuildCommand = "cargo build --release --package=sp1-cli --bin=${name}";
                installPhase = ''
                  mkdir -p $out/bin
                  cp target/release/${pname} $out/bin/${pname}
                '';
              };
            };

          formatter = pkgs.nixfmt-rfc-style;
        };
    };
}
