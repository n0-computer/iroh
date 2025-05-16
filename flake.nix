{
  description = "Iroh workspace flake (with crane, workspace build)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        craneLib = crane.mkLib pkgs;

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          cargoExtraArgs = "--features server";
        };

        workspace-artifacts = craneLib.buildDepsOnly (commonArgs // {
          pname = "iroh-workspace";
        });

        iroh-relay = craneLib.buildPackage (commonArgs // {
          pname = "iroh-relay";
          cargoArtifacts = workspace-artifacts;
          doCheck = false;
          cargoBuildCommand = "cargo build --release --bin iroh-relay";
          installPhase = ''
            mkdir -p $out/bin
            cp target/release/iroh-relay $out/bin/
          '';
        });

        iroh-dns-server = craneLib.buildPackage (commonArgs // {
          pname = "iroh-dns-server";
          cargoArtifacts = workspace-artifacts;
          doCheck = false;
          cargoBuildCommand = "cargo build --release --bin iroh-dns-server";
          installPhase = ''
            mkdir -p $out/bin
            cp target/release/iroh-dns-server $out/bin/
          '';
        });
      in {
        packages.iroh-relay = iroh-relay;
        packages.iroh-dns-server = iroh-dns-server;
        devShells.default = craneLib.devShell {
          checks = { workspace = workspace-artifacts; };
          packages = [ pkgs.rust-analyzer pkgs.bashInteractive ];
        };
      }
    );
}