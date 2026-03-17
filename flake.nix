{
  description = "Development environment for iroh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustStable = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        rustNightly = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
        };

        commonInputs = with pkgs; [
          pkg-config
          llvmPackages.clang
          llvmPackages.bintools
          cargo-nextest
          cargo-deny
          cargo-make
        ];
      in
      {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [ rustStable ] ++ commonInputs;

            RUST_BACKTRACE = "1";
          };

          nightly = pkgs.mkShell {
            buildInputs = [ rustNightly ] ++ commonInputs;

            RUST_BACKTRACE = "1";
          };
        };
      }
    );
}
